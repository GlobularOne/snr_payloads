#!/usr/bin/python3
"""
Payload showing skull and bones on a red background, pranking purposes only.
It should be executed as an executable using run_executable payload
"""
import shutil
import time
from libsnr.payload.safety_pin import require_lack_of_safety_pin

LICENSE = "Apache-2.0"
AUTHORS = ["GlobularOne"]

TERM_COLOR = "\033[41;30m"
FLAG = r"""\
                               ______
                            .-"      "-.
                           /            \
               _          |              |          _
              ( \         |,  .-.  .-.  ,|         / )
               > "=._     | )(__/  \__)( |     _.=" <
              (_/"=._"=._ |/     /\     \| _.="_.="\_)
                     "=._ (_     ^^     _)"_.="
                         "=\__|IIIIII|__/="
                        _.="| \IIIIII/ |"=._
              _     _.="_.="\          /"=._"=._     _
             ( \_.="_.="     `--------`     "=._"=._/ )
              > _.="                            "=._ <
             (_/                                    \_)
"""


def main():
    require_lack_of_safety_pin()
    print("\033[2J", end="")
    print(TERM_COLOR, end="")
    terminal_size = shutil.get_terminal_size()
    print(" " * (terminal_size.columns * terminal_size.lines), end="")
    print(FLAG)
    while True:
        time.sleep(10)


if __name__ == "__main__":
    main()
