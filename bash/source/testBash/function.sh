print_name() {
  echo "first params: $1!"
  echo "second params: $2!"
  echo "all params: $@!"
  echo "all params: $*!"
  echo "params number: $#!"
}

print_name a b c d
print_name a b
