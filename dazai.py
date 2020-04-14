import os
import subprocess
import time
import datetime
import sys
import re
os.system('adb devices 2>/dev/null')
os.system('clear')

o = "\033[1;35;43m"
orange = "\033[1;33;40m"
red = "\033[1;31;40m"
clear = "\033[0;0;0m"
print o + '''

'''+clear+'''                                                               '''+o+'''&&&&&&&&&&@@
'''+clear+'''                                                   '''+o+'''&@@@&%######################%&@&&%%
'''+clear+'''                                               '''+o+'''%@&%#&&####################################%@&&&&&&&&&&&&&&&%%%%%%%%%%%%%%%&&&&&&&&&&&&&&&&'''+clear+'''              
'''+o+'''########################%%%%%%%%%%%%%%%%%%%%%&&################################&###########%#####&@&&&&&&&&&%%%%%%%%%%%%%%%&&&&&&&&&&&&&&&'''+clear+'''     
'''+o+'''##########################%%%%%%%%%%%%%%%#@######################&%############%@##############%##%%##&&&&&&%%%%%%%%%%%%%%%&&&&&&&&&&&&&&&'''+clear+'''    
'''+o+'''#############################%%%#%#%#%%&#######################@%################@#%##############%%%%%%%%&@%%%%%%%%%%%%%%%&&&&&&&%%%%&&&&'''+clear+'''     
'''+o+'''################################%##%@%######################%@&%################%%&########%%%%%##%%%#%&&%%%#&@&%%%%%%%%%%%&&&%%%%%%%%%%%%'''+clear+'''
'''+o+'''################################%@%#######################%@&&&##################%&@&##%#######%%%%%%%%%#@&&&%%%@@%%%%%%%%%&&&&&&&%%%%%%%%
##############################%&#########################@&&&@#####################@&&@%%%%%%%%%%%%%%%%%%#&&&&@&#&@&%%%%%%%%&&&&&&&&%%%%%%
############################%&###########&%############&@%#&&@###################%%&&%&&@%##%%%%%%%%%%%%%%#&&&&&&&&@@#%%#%%%%%%&&&&%%%%%%%
##########################%&##########%&##############@%###%&&#####################%@#%#&&@#%%%%%%%%%%%%%%%%&@&&&&&&&@###%%%%%&&&&%&%%%%%%'''  +orange+'                   Dazai v1.0 by paSHA3'+o+'''
#########################&%##########&&#############%%######@@###################%%#@##%%#&@%%%%%%%%%%%%%%%%%&&&&&@@&&@##%%%%%%&%%%%%%%%%%'''+ clear +'            [-----Android Forensics Tool-----]'+ o + '''
########################%%#########(&&###########%#%%########@################&%%#%#&#%##%%%%%%%%%%%%%%%%%%%%%&&&&&@@&&@#%%%%%%%%%%%%%%%%%
#(((###################(&###&######&@#######&#####%%########%%%%#############%#&#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%@&&&@@&@&@#%&&%%%%%%%%%%%%%'''+ clear +orange+'            [+]'+clear+ 'Choose Number:'+clear+ o +'''
((#####################@###&#&####%&#######@######&######%%###&################@%#%%%%%%%#%%&#%%%@%%%%%%%%%%%%%%@&&&&@&@@%%%%%%%%%%%%%%%%%
((###################(@###&#@&####&%######@%#############&##%##&%##########%%%%&@%%%%%%%%%%%@%%%%%@&%%%%%%%%%%%%@@&@&@&&@@%%%%%%%%%%%%%%%%'''+ clear +'            [1] List supported file system'+ o +'''
#####################@###&%@&&###&&######&&#############&%#################%%#%&@%%%%##@%%%%%&%%%%%@%%%%%%%%%%%%@@@&&@@&&&@&%%%%%%%%%%%%%%'''+ clear +'            [2] List Mount Point'+ o +'''
((#########(######(%&####&&&&@###&#######@&#############@##########%#%%%#%%%%%%&&%%%%%#@%%%%%@%%%%%&@%%%%%%%%%%%@&@@&@&&@&&@%%&%%%%%%%%%%%'''+ clear +'            [3] Create Device Backup'+ o +'''
(((((((####((((#((&%####%@##&&&#########&&&############%@##########&%%#%%%%%%#%&&&%%%%%@%%%%%@&%%%%%@&%%%%%%%%%@&&&@&@&&&&&&@&&&%%%%%%%%%%'''+ clear +'            [4] Pull system storage'+ o +'''
(((#(((####((((#(&###%&#&%###%&&########&&&####%%######&#%%########&&#%%%%%%#%%@&&%%%%%@%%&%%@&&%%%%@&%%%%%%%%&@&&&&@@&&&&@&&@%&%%%%%%%%%%'''+ clear +'            [5] Pull sdcard storage'+ o +'''
((((((((###(#(#(&%###@##&######&@%#####%&&&####%%%#%#%#&/&#%####%##&@#%%%%%%%%%@&&%%%%&&%%&%%#&&&&%%@&&%%%%%%&@&&&&&@&&&&&@@&&@%%%%%%%%%%%'''+ clear +'            [6] Dump message buffer of the kernel '+ o +'''
((((((((((##((#(@###@&##&########%@%###&&&&####@&%#&###&,(%%####%%%&&%%%%%%%%%%@&&#%%@(&%%@%&((&&&@%@@&%%%%%%&&&&&&&&&&&&&&@&@@&%%%%%%%%%%'''+clear+' 	      [7] Applications Memory Usage'+ o +'''
(((((((########(&%#&&########@#########&&&&%##&(&#&@%##&/*&%%%%%%%%&&&%%%%%%%%#@&%%%@@@%%@&%@#(/%@&&&@&%%%%&&&&&@&&&&&&&&&&@@&&@%%%%%%%%%%'''+clear+' 	      [8] CPU Usage'+ o +'''
'''+o+'''(((((((##########&%#@#######@##########%&&&&#&#/&%%/&#%&/((&%%%%%%&&&@%%%%%%%%%@&%#@((&%&(&@/((((%@&&@&%%%&&%%&&@@&&&&&&&&&@%@&@%%%%%%%%%%'''+clear+' 	      [9] Dump Running Services'+ o +'''
'''+o+'''((((((((####(####(@#&######%&##########%&&&&&%**%#..*%#%/(((&#&%%%&&&@%%%%%%%%%&&%@&%%%&#(&#(((((((@&@&%%&%%%&&&&@&&&&&&&&&@%&@&%%%%%%%%%%'''+clear+'            [10] Dump Wifi Info'+ o +'''
'''+o+'''((((((((#########((#&######&############@&&&&..%/. ...###...(&&#%%&&&@%%%%%%%%&&%@#..&,... (((((((((@&&%%%%%%&&&&@&&&&&&@&@%%%@%%%%%%%%%%%'''+clear+'            [11] Battery Info'+ o +'''
'''+o+'''(((((((((((#(((((((#&#%####@######%%####@&&&/ /,....,,,/&( ..,%%%%&&&@%%%%%%%#&&(//(&#%&&&&&&&&&&&%(#@&%%&%%&&&&&&@&&&&&&@%%%&%&%%%%%%%%%%'''+clear+'            [12] Dump Data Sync'+ o +'''
'''+o+'''/((((((((((((((#(#(##&%####&######%&####%&&%/&&%%%%&@#///%&#/*/%&&&&&@%%%%%%%%&((,(&&%%&&&&. ...//&&%@%%%@%%&&&&&&@&&&&&&&@%%&%%%%%%%%%%%%'''+clear+'            [13] Directory Info'+ o +'''
'''+o+'''***///((((((((((###((%&##%#@######%@%##%#%&(,&&/#&%,     ,//(/*%%.&&&&%%%%%%%#%,.../&//*/%#. . ./#(%%&%%&&#&&&&&&&@&&&&&&&&@&%%&%%%%%%%%%%
..,,,**///((((((((((#(@%&##@##%#&%#%&%%%%#%(..*##//%%%%##(*. .%%../@&%%%%%%%%#%/..  .......   .. (((@%%%&&&&&&&&&@@&&&&&&@&&@&&&%%%%%%%%%%
......,,,**///(((((((%%#&#%%%###&###&&&%%##%* ..      ..   .. &,.(/(@%%%%%%%#%##..             ..*(&%%%&@&&&&&&&&@@&&&&&&@@&&@&%%%%%%%%%%%'''+clear+orange+'            Special Command for full report:'+clear+ o +'''
...........,,,**//#&%&&&%##%@#%%&#%%%%&@%#%%##.              /. ((/&##%..,%##%#%*.          .  ../&%%%&&&&&&&&&&&@&&&&&&&@#@&&@%%%%%%%%%%%'''+clear+'            [dazai] Give output as Report.html'+ o +'''
 ..............,,,**//#%#%%&&&#&&%%%%%#@&&&#%%%(..          .. ,/(%%%..   ..%###%,..        ...(&%#%&&&&&&&&&&&&&@&&&&&&@%%&&&@%%%%%%%%%%%
  ..............,.,(%###%&&&&&%&&&#%#%%#&&&&&@%%##. ..        . *%#(.        .,%##*.      .*#%%&%#@&&&&&&&&&&&&@&@&&&&&@%#%&&@%%%%%%%%%%%%
 ................,*(#(/,##&&&&&&&&%#%%%%%%&&&&&%#,/(#/.        .. ,*           ...,,       .  ##%,(@&&&&&&&&&&&@&@&&&&@###%@@%%%%%%%%%%%%%
  ...............,,.,,,,%#%&&&&&&&&%%%%%%%%%&%.(%(.  .                                     . ,%..*&&&&&&&&&&&&&&@&&&&&##(#@%%%%%%%%%%%%%%%
   ...................,,%(%&*(%&&&&&&#%#%%%%%#%..% .             ..%..   ..                 .*../&&&&&&&&&&&&&@&&@@&&(((##%%%%%%%%%%%%%%%%
    ................,,,,*##&,,,(&%%&&&%#%%%%%##%#.                 .//  ..                  ../&&&&&&&&&&&&&&@&&&&&&###(##%%%%%%%%%%%%%%%%
    .................,,,,,##*,,,,%%&&&&&%%%%%#%##%/                                        . (&&&&&&&&&&@&&@@&&&&@&&&(#(##%%%%%%%%%%%%%%%%
     .................,,,,,,(/.,,##*%&&&&&&%%%#%%##%.                           .          .#&&&&#@&&&&&&&&&&&&&&&#@&@%%##%%%%%%%%%%%%%%%%
       ...............,,,,,,,,,,,#,,*&&&&&&&&&&&(,*##        ,*.                 .,,     ..(&#((@&&&&@@&&&&&&@&&@(##(((((#%%%%%%%%%%%%%%%%
       ...............,,,,,,,,,,,,,,(%&%&&&&&%&%%&%..          . .  .            ..   . *((//&@&&&&&&&&&&&@%#@&@#####((((#%%%%%%%%%%%%%%%%
        ...............,,,,,,,,,.,,(%#%#*,(&%%*%&%%%&( ..                       . . ..(((/%&&&&&&&&&@&&@%%%%%@%%#####(((##%%%%%%%%%%%%%%%%
        ................,,,,,,,,,(*,,,,,,***#&(*#%&&%%%%*.                       . *(//#&&&#&&&&&&@%%&@@%%%%%%#######(((##%%%%%%%%%%%%%%%%
       ...................,,,,,,,,,,,,,,,,,*****(%*##%&%/(##..                 .,((/%&&&%&(&@&#@&#%%%%%&&%%%%%########((##%%%%%%%%%%%%%%%%
      ......................,,,,,,,,,,,,,,,,,,**( . ,. %. ,((#&/..       .  ..(/(%&&&&#&#%(%#(((@%%%%%%%%%%%%%############%%%%%%%%%%%%%%%%
     .......................,,,,,,,,,,,,,,,,,*,*#     (%. . ./((&&%/,   . ,(/#&&&&@%%#&/(((&((%(((@%%%%%%%%%%%############%%%%%%%%%%%%%%%%
    ......................,,,,,,,,,,,,,,,,,,,,,**/      ,%(. . ,(/(&&&%(/%&&&&@&@#%%(((((((&(%((((&%%%%%%%%%%%%###########%%%%%%%%%%%%%%%%
  .........................,,,,,,,,,,,,,,,,,,,,**(.        */,(*. /(((&&&&&&&@(%(((((((((%%&(((((%%##%%%%%%%%%%%##########%%%%%%%%%%%%%%%%
   .........................,,,,,,,,,,,,,,,,*,*(,**           (*  ((*(/(/%@&/(((((((/#%(((&((((((&((######%%%%%###########%%%%%%%%%%%%%%%%
     ........................,,,,,,,,,,,,,*,(*,*,/               *(   ,%%#((((((((&#(/((%(((((((%%%&((((((################%%%%%%%%%%%%%%%%
      .......................,,,,,,,,,,,,//,,,,(/                    .(.  (((%%(/(/(/(%(((((((((@###%&((((###(((((########%%%%%%%%%%%%%%%%
          ..................,,,,,,,,,,*(,,,,,,,/,                    /  (   ,(///(((((*/(%#((((#%%###%#%#((#(((((((((((((#%%%%%%%%%%%%%%%%
        .  .................,,.,.,,,,(,,,,,,,,,,(                 .#/(  .,     ,/(/(#%./((&((((((%#######@#((#(((((//////(##%%%%%%%%%%%%%%
           .................,..*((,,,#,,,,,,,,,,**                ,(/(*  /.(,  .(/ *#( (((&((((((&#######(@#%@%((((//////((#######%%%%%%%%
                         *(/,,,,,,,,,#,,,,,,,,,,,#.               *(/(/  ./     ,,. /. /((# *((((%%########&%###%&%//////((############%%%
'''+o+'''                    //,,,,,,,,,,,,,,,#,,,,,,,,,,,,#               (/(((  . #        (  ((/#   *((#@##########&#######%&(/((#####((########'''+ clear +'''
'''+o+'''             .*/,.,,,,,,,,,,,,,,,,,,,(,,,,,,,,,,,,,%              %//((     (#*    (, .(((#.    *#&###########&###########&&#(############'''+ clear +'''  
'''+o+'''      ,*(*,,,,,,,,,,,,,,,,,,,,,,,,,,(,,,,,,,,,,,,,*%,           ,%(/(*      ,,    #   *(((%,    /#&###########%%#############%@&##########'''+ clear +'''
'''+o+'''/*,,.,,,.,,.,,,.,,,,,,,,,,,,,,,,,,,,,(,,,,,,,,,,,,,,/#(         .%&&%#..      .*  /.    ,#(&&/   .%%############%@###################%@@&%'''+ clear +'''
'''+o+''',,,,,,,,,,,,,..,,,,,,,,,,,,,,,,,,,,,,(,,,,,,,,,,,,,,,((#.      .%(&&&##%,....   ( (  .....%%@##. .%(#*/###########&%######################'''+ clear +'''
''' + clear

command = "test"
root_d = 100
root_d = os.popen('adb root | grep -c production').read()
root_detect = int(root_d)

device = os.popen('adb devices | grep -c device 2>/dev/null').read()
device_model = os.popen("adb devices -l | awk '{ print $5 }' | sed 's/model:/    /'").read()
detect = int(device)

if detect > 1:
	print(orange + "[+] Device Detected:" + clear + device_model)

	if root_detect == 1:
		print(orange +"[+] Device Status: " + clear + "NON-ROOT")
		device_status = "NON-ROOT"

	elif root_detect == 0:
		print(orange + "[+] Device Status: " + clear + "ROOTED")
		device_status = "ROOTED"

	else:
		print(orange + "[+] Device Status: " + clear + "can't detect")
		device_status = "can't detect"

elif detect == 1:
	print(red + "[+] No Device Detected" + clear)
	print("   [1] Make sure that USB debugging mode is on")
	print("   [2] The device is connected properly")
	print("\n")
	command = "exit"

while command != "exit":

	command = raw_input("COMMAND"+orange+"|>" + clear)

	if command == "":
		command = ""

	elif command == "1":
		os.system('adb shell cat /proc/filesystems')

	elif command == "2":
		os.system('adb shell df')

	elif command == "3":
		os.system('adb backup -all -f backup.ab')
		directory = os.popen('pwd').read()
		directory_read = str(directory)
		print(orange + '[+] Backup Complete: ' + clear + directory_read + '/backup.ab' )

	elif command == "4":
		os.system('adb pull /system')
		print(orange + "SHA1SUM for directory:" + clear)
		os.system('tar cf - system | sha1sum')
		print(orange + "Verify using command: " + clear + "tar cf - system | sha1sum")

	elif command == "5":
		sd = os.popen("adb shell ls \\$EXTERNAL_STORAGE | grep -c sdcard").read()
		sd_card = int(sd)


		if sd_card == 1:
			os.system('adb pull /sdcard')
			print(orange + "SHA1SUM for directory:" + clear)
			os.system('tar cf - sdcard | sha1sum')
			print(orange + "Verify using command: " + clear + "tar cf - sdcard | sha1sum")

		else:
			print(red + "No sdcard present in device" + clear)

	elif command == "6":
		os.system("adb shell dmesg > kernel_message_buffer.txt")
		print(orange + "Dump saved as: " + clear + "kernel_message_buffer.txt")

	elif command == "7":
		 os.system("adb shell dumpsys meminfo > meminfo.txt")
		 print(orange + "Dump saved as: " + clear + "meminfo.txt")


	elif command == "8":
		 os.system("adb shell dumpsys cpuinfo")

	elif command == "9":
		os.system("adb shell service list > running_services.txt")
		print(orange + "Dump saved as: " + clear + "running_services.txt")


	elif command == "10":
		os.system("adb shell dumpsys wifi > wifi_info.txt")
		print(orange + "Dump saved as: " + clear + "wifi_info.txt")

	elif command == "11":
		os.system("adb shell dumpsys battery")
		print("")
		os.system("adb shell dumpsys power | grep mBatteryLevel= | sed 's/mBatteryLevel=/Battery Level: /'")
		print("")

	elif command == "12":
		print("Dumping Sync...")
		os.system("adb shell dumpsys > temp/dumpsys.md")
		with open('temp/dumpsys.md','r') as f:
			inp = f.read()
			matches = re.findall(r'\bRecent Sync History.*?(?=Recent|$)', inp, flags=re.DOTALL)
			print(matches[0])


	elif command == "13":
		print("Directory Info:")
		os.system("adb shell ls -l") 

	elif command == "exit":
		os.system('exit')

	elif command == "clear":
		os.system('clear')

	elif command == "help":
		print '''

          [+] Choose Number:

          [1] List supported file system
          [2] List Mount Point
          [3] Create Device Backup
          [4] Pull system
          [5] Pull sdcard
          [6] Dump message buffer of the kernel
          [7] Applications Memory Usage
          [8] CPU Usage
          [9] Dump Running Services
          [10] Dump Wifi Info
          [11] Battery Info
          [12] Dump Data Sync
          [13] Directory Info 


	  Special Command for full report:
	  [dazai] Give output as Report.html'''

	elif command == "dazai":
		print(orange +"[+]"+clear+"Generating Report...")
		print(" ")

		dir_exist = os.popen("ls | grep -c report").read()
		mount_p = os.popen('adb shell df').read()
		R_DIR = int(dir_exist)

		if R_DIR == 1:
			os.system("rm -r report && mkdir report")

		elif R_DIR == 0:
			os.system("mkdir report")

		else:
			print("Something went wrong")

		print(orange + "[+]" + clear + "Building Essntials")
		os.system("cp temp/dazai.gif report/dazai.gif")
		os.system("cp temp/typeface/BOLD/HomepageBaukasten-Bold.otf report/HomepageBaukasten-Bold.otf")
		os.system("cp temp/typeface/BOOK/WEB/HomepageBaukasten-Book.ttf report/HomepageBaukasten-Book.ttf")
		heading = "Dazai v1.0"

		print(orange + "[+]" + clear + "Dumping Filsystem")
		os.system('adb shell cat /proc/filesystems > report/fs.txt')
		print(orange + "[+]" + clear + "Dumping Mount Point")
		os.system('adb shell df > report/mount.txt')
		os.system("cat report/mount.txt | sed 's/Filesystem               Size     Used     Free   Blksize/Filesystem               Size     Used   Free  Blksize/' > report/mount_p.txt")
		os.system('rm report/mount.txt')
		print(orange + "[+]" + clear + "Dumping Kernel Buffer")
		os.system('adb shell dmesg > report/kernel_message_buffer.txt')
		print(orange + "[+]" + clear + "Dumping Meminfo")
		os.system("adb shell dumpsys meminfo > report/meminfo.txt")
		print(orange + "[+]" + clear + "Dumping CPU Logs")
		os.system("adb shell dumpsys cpuinfo > report/cpuinfo.txt")
		print(orange + "[+]" + clear + "Dumping Running Services")
		os.system("adb shell service list > report/running_services.txt")
		print(orange + "[+]" + clear + "Dumping Wifi Info")
		os.system("adb shell dumpsys wifi > report/wifi_info.txt")
		print(orange + "[+]" + clear + "Dumping Battery Info")
		os.system("adb shell dumpsys battery > report/battery.txt")
		print(orange + "[+]" + clear + "Dumping Directory Info")
	  	os.system("adb shell ls -l > report/dir_info.txt")


	  	print(orange + "[+]" + clear + "Dumping Recent Sync")
		os.system("adb shell dumpsys > temp/dumpsys.md")
		with open('temp/dumpsys.md','r') as f_sync:
			inp = f_sync.read()
			matches = re.findall(r'\bRecent Sync History.*?(?=Recent|$)', inp, flags=re.DOTALL)
			os.system('touch report/sync.txt')
			
			f_sync_result = open('report/sync.txt','wb')
			f_sync_result.write(matches[0])
			f_sync_result.close()

	  		print(orange + "[+]" + clear + "Dumping CPU Info")		
			os.system("adb shell cat /proc/cpuinfo > report/the_cpu_info.txt")

			print(orange + "[+]" + clear + "Dumping VM states")
			os.system("adb shell cat /proc/vmstat > report/vmstat.txt")

		sim_ss1 = os.popen('adb shell getprop ril.imsi.status.sim1').read()
		sim_ss2 = os.popen('adb shell getprop ril.imsi.status.sim2').read()


		sim_s1 = int(sim_ss1)
		sim_s2 = int(sim_ss2)

		if sim_s1 == 1:
			sim_slot1 = "Sim1: Active"

		elif sim_s1 == 0:
			sim_slot1 = "Sim1: inactive"

		else:
			sim_slot1 = "can't detect"

		if sim_s2 == 1:
			sim_slot2 = "Sim2: Active"

		elif sim_s2 == 0:
			sim_slot2 = "Sim2: inactive"

		else:
			sim_slot2 = "can't detect"



		f = open('report/Report.html','wb')
		message = """<html>
		<head></head>
		<body style="background-color:white;color:black">
		<style>
		@font-face {
  			font-family: gotham;
  			src: url(HomepageBaukasten-Bold.otf);

  			}

  		@font-face {

  		font-family: gotham_l;
  		src: url(HomepageBaukasten-Book.ttf);
  		}

		h1 {
  			font-family: gotham;
		    }

		h2 {
  			font-family: gotham_l;
  			color: black;
		    }

		 object:focus {
  			outline: none;
  			color: white;

				}

		iframe{
    		border:none;
   			width:400px;
    		display:block;
    		color: white;
			}

		.parent {
  		padding: 1rem
		}

		.child {
  			padding: 1rem
			}

		.inline-block-child {
  		display: inline-block;
		}


		</style>
		<h1 font-face="gotham">""" + heading + """</h1>
		<img src="dazai.gif" alt="Here is your report..." ">
		<p style="padding-left: 180px;">"report is ready sir..."</p>


		<div class='parent'>

		<div class='child inline-block-child'>
		<h1>  """ + "Scan perform on:" +"""</h1>"""+"""
		<h2>"""+os.popen('date').read()+"</h2>"+"""
		</div>

		<div class='child inline-block-child'>
		<h1>  """ + "Device Name:" +"""</h1>"""+"""
		<h2>"""+device_model+"</h2>"+"""
		</div>


		<div class='child inline-block-child'>
		<h1>  """ + "Device Status:" +"""</h1>"""+"""
		<h2>"""+device_status+"</h2>"+"""
		</div>


		<div class='child inline-block-child'>
		<h1>  """ + "Device Timezone:" +"""</h1>"""+"""
		<h2>"""+os.popen('adb shell getprop persist.sys.timezone').read()+"</h2>"+"""
		</div>

		<div class='child inline-block-child'>
		<h1>  """ + "Sims Slot:" +"""</h1>"""+"""
		<h2>"""+os.popen('adb shell getprop ro.telephony.sim.count').read()+"</h2>"+"""
		</div>

		<div class='child inline-block-child'>
		<h1>  """ + "Sims Slots" +"""</h1>"""+"""
		<h2>"""+sim_slot1+"</h2>"+"""
		<h2>"""+sim_slot2+"</h2>"+"""
		</div>

		<div class='child inline-block-child'>
		<h1>  """ + "Sim Company:" +"""</h1>"""+"""
		<h2>"""+os.popen("adb shell getprop gsm.sim.operator.alpha | sed 's/,/ /'").read()+"</h2>"+"""
		</div>

		<div class='child inline-block-child'>
		<h1>  """ + "Account's Dump:" +"""</h1>"""+"""
		<h2>"""+os.popen('adb shell dumpsys | grep "Account {"').read()+"</h2>"+"""
		</div>

		<div class='child inline-block-child'>
		<h1>  """ + "Kernel Version:" +"""</h1>"""+"""
		<h2>"""+os.popen('adb shell cat /proc/version').read()+"</h2>"+"""
		</div>

		</div>




		<div class='parent'>
		<div class='child inline-block-child'>
		<h1>  """ + "Supported File System:" +"""</h1>"""+"""
  		<iframe src="fs.txt" frameborder="0" height="200" width="95%"></iframe>
		</div>

		<div class='child inline-block-child'>
		<h1>  """ + "Mount Points:" +"""</h1>"""+"""
  		<iframe src="mount_p.txt" frameborder="0" height="450" width="10"></iframe>
		</div>

		<div class='child inline-block-child'>
		<h1>  """ + "Battery Info:" +"""</h1>"""+"""
  		<iframe src="battery.txt" frameborder="0" height="450" width="10"></iframe>
		</div>


		<div class='child inline-block-child'>
		<h1 style="padding-top: 20px;">  """ + "CPU Logs:" +"""</h1>"""+"""
		<button onclick=" window.open('cpuinfo.txt','_blank')"> See Logs</button>
		</div>

		<div class='child inline-block-child'>
		<h1 style="padding-top: 20px;">  """ + "Service List:" +"""</h1>"""+"""
		<button onclick=" window.open('running_services.txt','_blank')"> See Logs</button>
		</div>


		
		<div class='child inline-block-child'>
		<h1 style="padding-top: 20px;">  """ + "Wifi Info:" +"""</h1>"""+"""
		<button onclick=" window.open('wifi_info.txt','_blank')"> See Logs</button>
		</div>

		<div class='child inline-block-child'>
		<h1 style="padding-top: 20px;">  """ + "kernel message buffer:" +"""</h1>"""+"""
		<button onclick=" window.open('kernel_message_buffer.txt','_blank')"> See Logs</button>
		</div>


		<div class='child inline-block-child'>
		<h1 style="padding-top: 20px;">  """ + "Applications Memory Usage:" +"""</h1>"""+"""
		<button onclick=" window.open('meminfo.txt','_blank')"> See Logs</button>
		</div>

		<div class='child inline-block-child'>
		<h1 style="padding-top: 20px;">  """ + "Data Sync:" +"""</h1>"""+"""
		<button onclick=" window.open('sync.txt','_blank')"> See Logs</button>
		</div>

		<div class='child inline-block-child'>
		<h1 style="padding-top: 20px;">  """ + "Directory Info:" +"""</h1>"""+"""
		<button onclick=" window.open('dir_info.txt','_blank')"> See Logs</button>
		</div>

		<div class='child inline-block-child'>
		<h1 style="padding-top: 20px;">  """ + "CPU Info:" +"""</h1>"""+"""
		<button onclick=" window.open('the_cpu_info.txt','_blank')"> See Logs</button>
		</div>


		<div class='child inline-block-child'>
		<h1 style="padding-top: 20px;">  """ + "Virtual memory stats:" +"""</h1>"""+"""
		<button onclick=" window.open('vmstat.txt','_blank')"> See Logs</button>
		</div>		






		</div>

		</body>
		</html>"""
		f.write(message)
		f.close()
		print(" ")
		print(orange +"[+]"+clear+"Report Generated: /report/Report.html")




	else:
		print(red + "Invalid command" + clear)


