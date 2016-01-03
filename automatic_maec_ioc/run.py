from sys import stdout
import time
from multiprocessing import Process,Manager,Queue
from server.init_server import InitServer
from gui.simplegui import SimpleGUI
from Tkinter import Tk
from server.task_server import TaskServer
from server.iocserver import IOCServer

def countdown(t):
    while t:

        formattime="Waitng for...  %d \r"%t
        stdout.write(formattime)
        stdout.flush()
        time.sleep(1)
        t -= 1
    print("Continue...")

def runconsoleinit(queue,title,labelname):
    root=Tk()
    root.title(title)
    SimpleGUI(queue=queue,parent=root,label=labelname)
    root.mainloop()

def runconsoletask(queue,title,labelname):
    root=Tk()
    root.title(title)
    SimpleGUI(queue=queue,parent=root,label=labelname)
    root.mainloop()

def runconsoleioc(queue,title,labelname):
    root=Tk()
    root.title(title)
    SimpleGUI(queue=queue,parent=root,label=labelname)
    root.mainloop()

def run_init_server(console_queue,analyzers):
    InitServer(console_queue,analyzers).run()

def run_task_server(console_queue,analyzers,active_analyzers):
    TaskServer(console_queue,analyzers,active_analyzers).run()

def run_ioc_server(console_queue,analyzers,active_analyzers):
    IOCServer(console_queue,active_analyzers,analyzers) .run()

if __name__=='__main__':
    manager = Manager()
    analyzers = manager.dict()
    active_analyzers = manager.dict()
    console_init_server=Queue()
    console_task_server= Queue()
    console_ioc_server = Queue()
    print('Starting machine....')
    p_init_server_console  = Process(target=runconsoleinit,args=(console_init_server,'Terminal','Init Server'))
    pinit= Process(target=run_init_server,args=(console_init_server,analyzers,))
    p_task_server_console = Process(target=runconsoletask,args=(console_task_server,'Terminal','Task Server'))
    ptask= Process(target=run_task_server,args=(console_task_server,analyzers,active_analyzers,))
    p_ioc_server_console= Process(target=runconsoleioc,args=(console_ioc_server,'Terminal','IoC Server'))
    pioc= Process(target=run_ioc_server,args=(console_ioc_server,analyzers,active_analyzers,))

    p_init_server_console.start()
    pinit.start()
    countdown(40)
    p_task_server_console.start()
    ptask.start()
    p_ioc_server_console.start()
    pioc.start()

    countdown(20)
    pinit.terminate()
    p_init_server_console.terminate()
    ptask.terminate()
    p_task_server_console.terminate()
    pioc.terminate()
    p_ioc_server_console.terminate()

    '''
    PATH=os.path.join(os.path.abspath('.'),'server')
    print('Starting init server ....')
    init_server_path=os.path.join(PATH,'init_server.py')
    command='python %s'%init_server_path
    com_shell  ="\"%s; exec $SHELL\""%command
    gnome_command="gnome-terminal -x bash -c %s"%com_shell
    subprocess.call(gnome_command,shell=True)
    countdown(120)
    print('Starting task server ....')
    task_server_path=os.path.join(PATH,'task_server.py')
    command='python %s'%task_server_path
    com_shell  ="\"%s; exec $SHELL\""%command
    gnome_command="gnome-terminal -x bash -c %s"%com_shell
    subprocess.call(gnome_command,shell=True)
    #check if init_server_run....
    countdown(30)

    #Run ioc Server....................
    '''
