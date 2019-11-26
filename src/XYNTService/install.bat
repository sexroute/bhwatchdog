net stop UI0Detect 
sc config UI0Detect start= disabled
echo disabled UI0Detect
BHWatchDogService.exe -i