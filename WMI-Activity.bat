logman create trace "wmi-activity" -ow -o %0\..\wmi-activity-%COMPUTERNAME%.etl -p "Microsoft-Windows-WMI" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets

@rem WMI-Activity
logman update trace "wmi-activity" -p {1418EF04-B0B4-4623-BF7E-D74AB47BBDAA} 0xffffffffffffffff 0xff -ets

@echo off
echo
ECHO Reproduce your issue and enter any key to stop tracing
@echo on
pause
logman stop "wmi-activity" -ets
tasklist /svc > %0\..\tasklist-%COMPUTERNAME%.txt
 
@echo off
echo Tracing has been captured, wmi-activity.etl and tasklist.txt saved.
pause