import os,subprocess,time
print(os.path.abspath('.'))
PATH=os.path.join(os.path.abspath('.'),'server')
print('Staring init server ....')
init_server_path=os.path.join(PATH,'init_server.py')
command='python %s'%init_server_path
com_shell  ="\"%s; exec $SHELL\""%command
gnome_command="gnome-terminal -x bash -c %s"%com_shell
subprocess.call(gnome_command,shell=True)
#check if init_server_run....
time.sleep(120)
#Run ioc Server....................

