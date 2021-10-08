logman create trace "wmi-trace" -ow -o %0\..\wmi-trace-%COMPUTERNAME%.etl -p {1418EF04-B0B4-4623-BF7E-D74AB47BBDAA} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
logman update trace "wmi-trace" -p {1FF6B227-2CA7-40F9-9A66-980EADAA602E} 0xffffffffffffffff 0xff -ets
logman create trace "NT Kernel Logger" -ow -o %0\..\wmi-trace-kernel-%COMPUTERNAME%.etl -p {9E814AAD-3204-11D2-9A82-006008A86939} 0x1 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 512 -ets

@echo off
echo
ECHO Reproduce your issue and enter any key to stop tracing
@echo on
pause
logman stop "wmi-trace" -ets
logman stop "NT Kernel Logger" -ets
tasklist /svc > %0\..\tasklist-%COMPUTERNAME%.txt
 
@echo off
echo Tracing has been captured, wmi-trace.etl, wmi-trace-kernel and tasklist.txt saved.
pause