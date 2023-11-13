pub mod memsearch;
pub mod mmbnlc;

use crate::mmbnlc::*;
use mlua::prelude::*;

static mut HOOKS: Vec<ilhook::x64::HookPoint> = Vec::new();

#[allow(non_upper_case_globals)]
static EXE3_SceFlagRev2: std::sync::OnceLock<GBAFunc> = std::sync::OnceLock::new();

fn hook_direct(addr: usize, func: ilhook::x64::JmpToRetRoutine, user_data: usize) {
    let hooker = ilhook::x64::Hooker::new(
        addr,
        ilhook::x64::HookType::JmpToRet(func),
        ilhook::x64::CallbackOption::None,
        user_data,
        ilhook::x64::HookFlags::empty(),
    );
    let hook = unsafe { hooker.hook() };
    let hook = hook.expect(format!("Failed to hook {addr:#X}!").as_str());

    unsafe { &mut HOOKS }.push(hook);
}

#[mlua::lua_module]
fn patch(lua: &Lua) -> LuaResult<LuaValue> {
    let text_section = lua
        .globals()
        .get::<_, LuaTable>("chaudloader")?
        .get::<_, LuaTable>("GAME_ENV")?
        .get::<_, LuaTable>("sections")?
        .get::<_, LuaTable>("text")?;
    let text_address = text_section.get::<_, LuaInteger>("address")? as usize;
    let text_size = text_section.get::<_, LuaInteger>("size")? as usize;

    // Find EXE3_SceFlagRev2
    println!("Searching for EXE3_SceFlagRev2...");
    let ptrs_sce_flag_rev2 = memsearch::find_n_in(
        "48895C2408 48896C2410 4889742418 57 4154 4155 4156 4157 4883EC20 4C8BE9 488D0Dxxxxxxxx E8xxxxxxxx 41C7453CA3280000",
        text_address, text_size, 1
    );
    if ptrs_sce_flag_rev2.is_err() || ptrs_sce_flag_rev2.as_ref().unwrap().len() != 1 {
        panic!("Cannot find EXE3_SceFlagRev2!");
    }
    EXE3_SceFlagRev2
        .set(unsafe { std::mem::transmute(ptrs_sce_flag_rev2.unwrap()[0]) })
        .unwrap();
    println!("Found EXE3_SceFlagRev2 @ {:#X}", *EXE3_SceFlagRev2.get().unwrap() as usize);

    // Find EXE3_PrgmCompCommandCheck
    println!("Searching for EXE3_PrgmCompCommandCheck...");
    let ptrs_prgm_comp_command_check_hook = memsearch::find_n_in(
        "488BCB C74338214F0000 E8xxxxxxxx 3D214F0000 0F85C4010000 8B4340 C1E802 A801 0F84E9000000 488D5310 488BCB",
        text_address, text_size, 2
    );
    if ptrs_prgm_comp_command_check_hook.is_err() || ptrs_prgm_comp_command_check_hook.as_ref().unwrap().len() != 2 {
        panic!("Cannot find EXE3_PrgmCompCommandCheck hooks!");
    }
    let ptrs_prgm_comp_command_check_hook = ptrs_prgm_comp_command_check_hook.unwrap();

    // Install hooks
    for addr in ptrs_prgm_comp_command_check_hook.iter() {
        println!("Hooking EXE3_PrgmCompCommandCheck @ {:#X}", *addr);
        hook_direct(*addr, on_test_flag, *addr);
    }

    Ok(LuaValue::Nil)
}

unsafe extern "win64" fn on_test_flag(
    reg: *mut ilhook::x64::Registers,
    _return_addr: usize,
    from_addr: usize,
) -> usize {
    let gba = GBAState::from_addr((*reg).rbx);

    // Skip the already compressed check and just reverse the flags
    gba.r0 = gba.r4;
    EXE3_SceFlagRev2.get().unwrap()(gba);
    gba.r0 = gba.r4 + 1;
    EXE3_SceFlagRev2.get().unwrap()(gba);
    gba.r0 = gba.r4 + 2;
    EXE3_SceFlagRev2.get().unwrap()(gba);
    gba.r0 = gba.r4 + 3;
    EXE3_SceFlagRev2.get().unwrap()(gba);

    // Skip over the existing code that sets the flags
    // and go to the part where the sound effect gets played
    from_addr + 0xB6
}
