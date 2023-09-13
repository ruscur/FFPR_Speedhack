# Final Fantasy Pixel Remaster speedhack

A script to modify battle speed in the Final Fantasy Pixel Remaster series:

- supports FFI, FFII, FFIII, FFIV, FFV, FFVI (probably)
- set autobattle speed from 1.5x to 5x
- make battles always run at autobattle speed regardless of mode

## Requirements

The script is written in [Python 3](https://www.python.org/downloads/) and depends on the [Capstone](https://www.capstone-engine.org/) disassembler and [pefile](https://github.com/erocarrera/pefile) parser.

You can install them with `pip3 install -r requirements.txt`

Should work on any operating system that supports the above requirements but I've only tested it on Linux.

## Usage

Run `python3 ffpr_speedhack.py`.  It expects the `GameAssembly.dll` file from the game you want to modify to be in the same directory it's running in.  You don't need to specify which game, they're all the same.

The script will ask you what you want to change.

The script will create a new `.dll` file that you can use in place of your original `GameAssembly.dll`.  Make sure to back up the original!

## Notes

If a game update resets your changes, you should just be able to run the script again and repeat the process.

This cannot brick your game, if something does go wrong you can restore your backup file/reinstall.  It certainly doesn't go near your saves or anything else important.

This isn't thoroughly tested on all the games - the disassembly and DLL creation works, but I haven't played them all to check it actually works in game (though I don't know why it wouldn't).  Open an issue if something doesn't work.

## Why?

This approach is (hopefully) resilient to patches (and new games altogether).  Working purely with offsets (i.e. hex editing) is subject to breakage from minor patches, so instead we disassemble the code to make sure we find exactly what we're looking for. Unless there's changes to the specific engine components this script adjusts, the method will keep working.

## Method

A function called in battles in all the FFPR games contains (approximately) this:

```c
bool in_autobattle_mode = get_autobattle_flag();
if (in_autobattle_mode)
	battle_speed *= *autobattle_multiplier;
```

Making the autobattle speed faster simply involves replacing the existing value (1.5x) with your desired speed.

Making battles always use the autobattle speed involves changing the code that determines the battle speed to always think `in_autobattle_mode` is true.

Rather than poke at hardcoded offsets, the script will instead do some fancy analysis to find what it's looking for.  This means it should work across game updates and most likely across new games running the same engine.

The script does the following:

- find the `get_autobattle_flag()` function by looking for `0fb64019`
- find the functions that call it, looking for the one we care about
- replace `if (in_autobattle_mode)` with `if (true)`
- find and replace the speed value

The code is in the `il2cpp` section and the speed value is in the `.rdata` section of `GameAssembly.dll`

## TODO

- automate backups?
- detect Steam directories to save manual DLL copying
  - sounds like too much hassle
- automate the font fixes while we're at it?
  - easy enough but then we have to know where the game folder is
- code is pretty gross
  
## License

This work is in the public domain and you can do whatever you want with it.

## Credits

I got the idea and general method from [eyrie0](https://steamcommunity.com/id/eyrie0) on Steam, who made some guides for hex editing the DLLs.  I saw that and wondered if I could automate the reverse engineering process and here we are.
