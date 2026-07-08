# Default batch GDB script (tool_id=gdb). Feed the PoV via stdin or --args as needed.
set pagination off
set confirm off
run
echo \n==== BACKTRACE ====\n
bt full
echo \n==== REGISTERS ====\n
info registers
echo \n==== MAPPINGS ====\n
info proc mappings
quit
