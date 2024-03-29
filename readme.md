MMBNLC EXE3 Navi Customizer Uncompress mod
==========================================

This is a mod for Mega Man Battle Network Legacy Collection Vol. 1 which enables
you to uncompress MMBN3 Navi Customizer programs which have previously been
compressed, just like in MMBN5 and MMBN6.

This can be useful for programs like SneakRun, where compressing the program
increases the minimum number of blocks that it takes up on the command line.


Features
--------

 *  Navi Customizer programs in MMBN3 can now be uncompressed again after they
    have been compressed.


Installing
----------

Windows PC and Steam Deck

 1. Download and install chaudloader:
    https://github.com/RockmanEXEZone/chaudloader/releases
    Version 0.11.0 or newer is required.

 2. Launch Steam in Desktop Mode. Right-click the game in Steam, then click
    Properties → Local Files → Browse to open the game's install folder. Then
    open the "exe" folder, where you'll find MMBN_LC1.exe.

 3. Copy the NaviCustUncompress_EXE3 folder to the "mods" folder.

 4. Launch the game as normal.


Version History
---------------

Ver. 1.1.0 - 13 November 2023

 *  Fixed potential crash when multiple code mods are active.
 *  Updated for compatibility with latest game update.
 *  chaudloader version 0.11.0 or newer is now required.

Ver. 1.0.1 - 15 October 2023

 *  Updated to work with Steam version 1.0.0.3.

Ver. 1.0.0 - 11 May 2023

 *  Initial version.


Building
--------

Building is supported on Windows 10 & 11. First install the following
prerequisites:

 *  Rust

Then, run one of the following commands:

 *  make - Builds the mod files compatible with chaudloader.
 *  make clean - Removes all temporary files and build outputs.
 *  make install - Installs the previously built mod files into the mods folder
    for chaudloader.
 *  make uninstall - Removes the installed mod files from the mods folder for
    chaudloader.
