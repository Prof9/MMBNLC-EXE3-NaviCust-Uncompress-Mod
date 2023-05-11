use ilhook::x64::{Hooker, HookPoint, HookType, JmpToRetRoutine, Registers, CallbackOption, HookFlags};
use std::os::raw::{c_int, c_void};
use winapi::{shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE}, um::winnt::DLL_PROCESS_DETACH};

pub mod memsearch;

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct GbaState {
    pub r0:  u32,  pub r1:  u32,  pub r2:  u32,  pub r3:  u32,
    pub r4:  u32,  pub r5:  u32,  pub r6:  u32,  pub r7:  u32,
    pub r8:  u32,  pub r9:  u32,  pub r10: u32,  pub r11: u32,
    pub r12: u32,  pub r13: u32,  pub r14: u32,  pub r15: u32,
    pub flags: u32,  pub flags_enabled: u32,
    pub ram: *const u8,
    pub unk50: u32, pub unk54: u32, pub unk58: u32, pub unk5c: u32,
    pub ldmia_stmia_addr: u32,
    pub stack_size: u32, pub call_depth: u32,
}

impl GbaState {
    pub fn read_u8(&self, addr: u32) -> u8 {
        unsafe { *(self.ram.offset(addr.try_into().unwrap())) }
    }

    pub fn from_addr<'a>(addr: u64) -> &'a mut Self {
        unsafe { &mut *(addr as *mut Self) }
    }
}

type GbaFunc = extern "C" fn(*const GbaState) -> u32;

static mut HOOKS: Vec<HookPoint> = Vec::new();

#[no_mangle]
pub extern "system" fn DllMain(_module: HINSTANCE, call_reason: DWORD, _reserved: LPVOID) -> BOOL {
    if call_reason == DLL_PROCESS_DETACH {
        unsafe { &mut HOOKS }.clear();
    }
    TRUE
}

fn hook_direct(addr: usize, func: JmpToRetRoutine, user_data: usize) {
    println!("Hooking {addr:#X}");
    let hooker = Hooker::new(
        addr,
        HookType::JmpToRet(func),
        CallbackOption::None,
        user_data,
        HookFlags::empty()
    );
    let hook = unsafe { hooker.hook() };
    let hook = hook.expect(format!("Failed to hook {addr:#X}!").as_str());

    unsafe { &mut HOOKS }.push(hook);
}

#[no_mangle]
pub unsafe extern "C" fn luaopen_patch(_: c_void) -> c_int {
    let image_base: usize = 0x140000000 as usize;
    let xtext_start: usize = unsafe { *((image_base+0x1E4) as *const u32) as usize + image_base };
    let xtext_size: usize = unsafe { *((image_base+0x1E8) as *const u32) as usize };

    // Find EXE3_SceFlagRev2
    let ptrs_sce_flag_rev2 = memsearch::find_n_in(
        "48895C2408 48896C2410 4889742418 57 4154 4155 4156 4157 4883EC20 4C8BE9 488D0Dxxxxxxxx E8xxxxxxxx 41C7453CA3280000",
        xtext_start, xtext_size, 1
    );
    if ptrs_sce_flag_rev2.is_err() || ptrs_sce_flag_rev2.as_ref().unwrap().len() != 1 {
        println!("Cannot find EXE3_SceFlagRev2");
        return 0;
    }
    let ptr_sce_flag_rev2 = ptrs_sce_flag_rev2.unwrap()[0];

    // Find hooks in EXE3_PrgmCompCommandCheck
    let ptrs_hook = memsearch::find_n_in(
        "488BCB C74338214F0000 E8xxxxxxxx 3D214F0000 0F85C4010000 8B4340 C1E802 A801 0F84E9000000 488D5310 488BCB",
        xtext_start, xtext_size, 2
    );
    if ptrs_hook.is_err() || ptrs_hook.as_ref().unwrap().len() != 2 {
        println!("Cannot find EXE3_PrgmCompCommandCheck hooks");
        return 0;
    }
    let ptrs_hook = ptrs_hook.unwrap();

    for addr in ptrs_hook.iter() {
        hook_direct(*addr, on_test_flag, *addr);
        hook_direct(*addr+0x3E, on_set_flag, ptr_sce_flag_rev2);
        hook_direct(*addr+0x72, on_set_flag, ptr_sce_flag_rev2);
        hook_direct(*addr+0xA6, on_set_flag, ptr_sce_flag_rev2);
        hook_direct(*addr+0xDA, on_set_flag, ptr_sce_flag_rev2);
    }
    0
}

extern "win64" fn on_test_flag(_reg: *mut Registers, _return_addr: usize, from_addr: usize) -> usize {
    // Here the game checks if the NCP is already compressed
    // We are going to skip this part
    from_addr + 0x28
}

extern "win64" fn on_set_flag(reg: *mut Registers, return_addr: usize, func_addr: usize) -> usize {    
    let gba = unsafe { GbaState::from_addr((*reg).rcx) };
    
    // Call EXE3_SceFlagRev2 instead of EXE3_SceFlagOn2
    #[allow(non_snake_case)]
    let EXE3_SceFlagRev2: GbaFunc = unsafe { std::mem::transmute(func_addr as *const GbaFunc) };
    (EXE3_SceFlagRev2)(gba);

    // Set correct return value
    unsafe { (*reg).rax = gba.r14 as u64; }
    // Skip original call
    return_addr + 0x5
}
