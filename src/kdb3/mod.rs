use std::mem;
use std::io::{Read, Cursor, Seek, SeekFrom};
use std::io;

use byteorder::{LittleEndian, ReadBytesExt};
use byteorder;

pub mod format;
mod nettle;

use kdb3::format::*;
use kdb3::nettle::*;


//
// Errors
//

#[derive(Debug)]
pub enum ParseError {
    Failure(&'static str),
    IoError(io::Error),
    ByteError(byteorder::Error),
}

impl From<byteorder::Error> for ParseError {
    fn from(err: byteorder::Error) -> ParseError {
        return ParseError::ByteError(err)
    }
}

impl From<io::Error> for ParseError {
    fn from(err: io::Error) -> ParseError {
        return ParseError::IoError(err)
    }
}


//
//
//

const KDB3_SIGNATURE: u64 = 0xB54BFB659AA2D903u64;
const KDB3_CIPHER_AES256_CBC: u32 = 2;


// Applies the KDB3 key transformation on the SHA-256 digest of the master key.
pub fn key_transform(master_key: &[u8; 32],
                     rounds_key: &[u8; 32],
                     rounds: u32,
                     final_seed: &[u8; 16]) -> [u8; 32] {

    let mut out = kdf_ecb_rounds(master_key, rounds_key, rounds);

    sha256_digest(out.as_ptr(), 32, out.as_mut_ptr());

    // Once more, for good luck
    kdf_sha256_final(final_seed, &mut out);

    out
}


// Compute the base master key from a passphrase.
//
// This is the first step in the key transformation phase.
pub fn transform_password(password: &[u8]) -> [u8; 32] {
    sha256_digest_new(password, password.len() as u32)
}


// Parse header and perform key transformation, returning the final key
fn parse_header(raw_master_key: &[u8; 32], header_data: &[u8; 124]) -> Option<Header> {
    let header: RawHeader;

    unsafe {
        header = mem::transmute_copy(header_data);
    }

    if header.signature != KDB3_SIGNATURE {
        println!("Signature mismatch");
        return None;
    } else if (header.flags & KDB3_CIPHER_AES256_CBC) == 0 {
        // TODO: other modes include Twofish and RC4
        println!("Unsupported cipher");
        return None;
    }

    let body_key = key_transform(raw_master_key,
                                 &header.seed_trans,
                                 header.key_rounds,
                                 &header.seed_final);

    Some(Header{
        key: body_key,
        iv: header.iv,
        hash: header.hash,
        groups: header.group_count as usize,
        entries: header.entry_count as usize,
    })
}


// Read fixed size string
//
// TODO: properly check trailing nul byte
fn read_str<R: Read + Seek>(size: usize, reader: &mut R) -> Result<String, ParseError> {
    if size == 0 {
        return Err(ParseError::Failure("Invalid string length"));
    }

    let mut part = reader.take(size as u64);
    let mut ret = String::new();

    match part.read_to_string(&mut ret) {
    Err(err) => Err(ParseError::IoError(err)),
    Ok(_) => Ok(ret.trim_right_matches('\u{0}').to_string())
    }
}


fn read_time<R: Read>(size: usize, reader: &mut R) -> Result<u64, ParseError> {
    let mut r: u64 = 0;

    for b in reader.take(size as u64).bytes() {
        match b {
        Err(err) => return Err(ParseError::from(err)),
        Ok(c) => r = (r << 8) | (c as u64),
        }
    }

    Ok(r)
}


fn read_uuid<R: Read>(size: usize, uuid: &mut [u8; 16], reader: &mut R) -> Result<(), ParseError> {
    if size != 16 {
        return Err(ParseError::Failure("Invalid UUID field size"));
    }
    try!(reader.read(uuid));
    Ok(())
}


// Parse a single group definition
fn parse_group<R: Read + Seek>(reader: &mut R) -> Result<Group, ParseError> {
    let mut group: Group = Default::default();
    loop {
        let field_type = try!(reader.read_u16::<LittleEndian>());
        let field_size = try!(reader.read_u32::<LittleEndian>());

        if field_type == KDB3_GROUP_END {
            if field_size != 0 {
                return Err(ParseError::Failure("Group end field not zero sized"));
            }
            break;
        }

        match field_type {
        KDB3_GROUP_ID       => group.id       = try!(reader.read_u32::<LittleEndian>()),
        KDB3_GROUP_IMAGE_ID => group.image_id = try!(reader.read_u32::<LittleEndian>()),
        KDB3_GROUP_FLAGS    => group.flags    = try!(reader.read_u32::<LittleEndian>()),
        KDB3_GROUP_LEVEL    => group.level    = try!(reader.read_u16::<LittleEndian>()),
        KDB3_GROUP_TITLE    => group.title    = try!(read_str(field_size as usize, reader)),

        0x0003 |
        0x0004 |
        0x0005 |
        0x0006 => {try!(reader.seek(SeekFrom::Current(field_size as i64)));},
        _ => {
                println!("Unhandled group field: {} ({})", field_type, field_size);
                try!(reader.seek(SeekFrom::Current(field_size as i64)));
            },
        }
    }

    Ok(group)
}


// Parse a single entry
fn parse_entry<R: Read + Seek>(reader: &mut R) -> Result<Entry, ParseError> {
    let mut entry: Entry = Default::default();
    loop {
        let field_type = try!(reader.read_u16::<LittleEndian>());
        let field_size = try!(reader.read_u32::<LittleEndian>());

        if field_type == KDB3_ENTRY_END {
            if field_size != 0 {
                return Err(ParseError::Failure("Group end field not zero sized"));
            }
            break;
        }

        match field_type {
        KDB3_ENTRY_TITLE    => entry.title    = try!(read_str(field_size as usize, reader)),
        KDB3_ENTRY_PASSWORD => entry.password = try!(read_str(field_size as usize, reader)),
        KDB3_ENTRY_USERNAME => entry.username = try!(read_str(field_size as usize, reader)),
        KDB3_ENTRY_URL      => entry.url      = try!(read_str(field_size as usize, reader)),
        KDB3_ENTRY_COMMENT  => entry.comment  = try!(read_str(field_size as usize, reader)),
        KDB3_ENTRY_GROUP_ID => entry.group_id = try!(reader.read_u32::<LittleEndian>()),
        KDB3_ENTRY_IMAGE_ID => entry.image_id = try!(reader.read_u32::<LittleEndian>()),

        KDB3_ENTRY_UUID => try!(read_uuid(field_size as usize, &mut entry.uuid, reader)),

        KDB3_ENTRY_CREATED  => entry.created  = try!(read_time(field_size as usize, reader)),
        KDB3_ENTRY_MODIFIED => entry.modified = try!(read_time(field_size as usize, reader)),
        KDB3_ENTRY_ACCESSED => entry.accessed = try!(read_time(field_size as usize, reader)),
        KDB3_ENTRY_EXPIRES  => entry.expires  = try!(read_time(field_size as usize, reader)),

        KDB3_ENTRY_BINARY |
        KDB3_ENTRY_BINARY_DESC => {
                //println!("Skipped entry field: {} ({})", field_type, field_size);
                try!(reader.seek(SeekFrom::Current(field_size as i64)));
            },
        _ => {
                println!("Unhandled entry field: {} ({})", field_type, field_size);
                try!(reader.seek(SeekFrom::Current(field_size as i64)));
            },
        }
    }

    Ok(entry)
}


// Decrypt and parse the groups and entries.
//
// TODO:
// - Cache the group hierarchy
// - Cache which group an entry belongs to
// - Consider storing the field_size per field as well
fn parse_body(header: &Header, body_data: &mut [u8]) -> Result<Database, ParseError> {
    let mut db: Database = Default::default();

    let data;
    match aes256_cbc_decrypt(&header.key, &header.iv, &header.hash, body_data) {
    None => return Err(ParseError::Failure("Failed to decrypt")),
    Some(d) => data = d,
    }

    let mut rdr = Cursor::new(data);

    for _ in 0..header.groups {
        let group = try!(parse_group(&mut rdr));
        db.groups.push(group);
    }

    for _ in 0..header.entries {
        let entry = try!(parse_entry(&mut rdr));
        db.entries.push(entry);
    }

    // Not an error per se, but probably indicates corruption
    let final_pos = rdr.position();
    try!(rdr.seek(SeekFrom::End(0)));
    db.trailing_data = rdr.position() != final_pos;

    Ok(db)
}


pub fn import(key: &[u8; 32], header_data: &[u8; 124], body_data: &mut [u8]) -> Result<Database, ParseError> {
    match parse_header(key, header_data) {
        None => Err(ParseError::Failure("Header error")),
        Some(header) => parse_body(&header, body_data),
    }
}
