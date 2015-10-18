//
// On-disk format
//

#[repr(C, packed)]
pub struct RawHeader {
    pub signature: u64,
    pub flags: u32,
    pub version: u32,
    pub seed_final: [u8; 16],
    pub iv: [u8; 16],
    pub group_count: u32,
    pub entry_count: u32,
    pub hash: [u8; 32],
    pub seed_trans: [u8; 32],
    pub key_rounds: u32,
}

//
//
//

#[derive(Debug)]
pub struct Header {
    pub key: [u8; 32],
    pub iv: [u8; 16],
    pub hash: [u8; 32],
    pub groups: usize,
    pub entries: usize,
}


#[derive(Default,Debug)]
pub struct Database {
    pub groups: Vec<Group>,
    pub entries: Vec<Entry>,

    pub trailing_data: bool,
}


// Group fields
pub const KDB3_GROUP_ID       : u16 = 0x0001;
pub const KDB3_GROUP_TITLE    : u16 = 0x0002;
pub const KDB3_GROUP_IMAGE_ID : u16 = 0x0007;
pub const KDB3_GROUP_LEVEL    : u16 = 0x0008;
pub const KDB3_GROUP_FLAGS    : u16 = 0x0009;
pub const KDB3_GROUP_END      : u16 = 0xFFFF;


#[derive(Default,Debug)]
pub struct Group {
    pub id: u32,
    pub image_id: u32,
    pub flags: u32,
    pub level: u16,
    pub title: String,
}


// Entry fields
pub const KDB3_ENTRY_UUID        : u16 = 0x0001;
pub const KDB3_ENTRY_GROUP_ID    : u16 = 0x0002;
pub const KDB3_ENTRY_IMAGE_ID    : u16 = 0x0003;
pub const KDB3_ENTRY_TITLE       : u16 = 0x0004;
pub const KDB3_ENTRY_URL         : u16 = 0x0005;
pub const KDB3_ENTRY_USERNAME    : u16 = 0x0006;
pub const KDB3_ENTRY_PASSWORD    : u16 = 0x0007;
pub const KDB3_ENTRY_COMMENT     : u16 = 0x0008;
pub const KDB3_ENTRY_CREATED     : u16 = 0x0009;
pub const KDB3_ENTRY_MODIFIED    : u16 = 0x000A;
pub const KDB3_ENTRY_ACCESSED    : u16 = 0x000B;
pub const KDB3_ENTRY_EXPIRES     : u16 = 0x000C;
pub const KDB3_ENTRY_BINARY_DESC : u16 = 0x000D;
pub const KDB3_ENTRY_BINARY      : u16 = 0x000E;
pub const KDB3_ENTRY_END         : u16 = 0xFFFF;

#[derive(Default,Debug)]
pub struct Entry {
    pub uuid: [u8; 16],
    pub group_id: u32,
    pub image_id: u32,
    pub title: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub comment: String,

    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
    pub expires: u64,
}
