██████  ██   ██  █████  ███    ██ ████████  █████  ██████  ██    ██ ████████ ███████ 
██   ██ ██   ██ ██   ██ ████   ██    ██    ██   ██ ██   ██  ██  ██     ██    ██      
██████  ███████ ███████ ██ ██  ██    ██    ███████ ██████    ████      ██    █████   
██      ██   ██ ██   ██ ██  ██ ██    ██    ██   ██ ██   ██    ██       ██    ██      
██      ██   ██ ██   ██ ██   ████    ██    ██   ██ ██████     ██       ██    ███████ 


This script was created to enable you to put Windows OS Hardening techniques into place simply. 
You will need to know what each technique means, what their impact is or could potentially be. 

The script will start by asking if you want to "Remediate" or "Reverse". 
  Remediate means to enable a more secure configuration for the listed items. 
  Reverse means to reverse the secure configuration back to the closest default setting possible. (Self documented inside of the script) 

The script will then ask if you want to create a new GPO, or modify an existing one

Then the script will ask you to give the name of the GPO, or name the new GPO. 

Next you will be asked if you want to Link the GPO to an OU, Unlink the GPO from an OU, or Skip. 
  If you select Link, or Unlink you will need to provide the distinguished name of the OU you want to link. 

Finally you will need to comma separated, add the corresponding numbers of the items you want to remediate comma separated (example: 1,2,3,4,17) 

After that, you will see output for each item selected. The GPO is created, and the changes should have been enacted. 
