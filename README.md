# Preface
There are a multitude of different ways to combat cheating in video games. Anti-cheating companies and gaming corporations take various approaches to deterring cheaters, typically employing a client-sided system such as Easy Anticheat, BattlEye or their own in-house solution to get the job done.

In this post, we will be discussing an anti-cheating solution known as Echo which differs from the standard approach. Echo is a tool predominently found within the minecraft PvP (player-vs-player) community and has recently bled its operations into games such as Rust or GTA's FiveM. Echo has a history of causing many issues and false bans due its primitiveness and substrata of false/inaccurate detections.

# How it works
Echo is a less than ideal solution for most as it requires manual intervention and analysis by staff/support members of the game/game server. Echo can be considered an "after the fact" anticheat mechanism, lacking any real time capabilities and relying merely on filesystem traces and memory artefacts in the hopes of catching cheaters. The suspected cheater is also granted a decent window of time to clear traces and other artefacts that could be picked up during the scan, which renders this system largely ineffective to above average cheat developers.

The typical procedure goes as follows:
 - Staff member freezes (preventing the user from moving/interacting in game) and notifies the suspected player not to log out/close the game. They demand the player to run Echo, providing them with a one time PIN to be used to initiate the scan.
 - Echo proceeds to scan the system as well as the games memory, looking for traces of cheating software (typically with known patterns, strings and other potential red flags)
 - Echo reports the results of the scan back to the staff member (saying what it found, if anything), which they look at and use their own judgement to decide whether to punish the player (typically a permanent ban).

# Analysis
Echo has two core components:
 - Usermode executable
   * Used to launch the scan, load the driver as well as display the GUI
 - Kernel driver
   * Used to interact with the virtual memory of the game/windows services

In this post, we will only be analyzing the kernel mode driver due to its easily exploitable nature as well as to demonstrate the lack of effort put into such a major component of this tool.
