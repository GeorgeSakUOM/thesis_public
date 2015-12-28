__author__ = 'george'
from Tkinter import Label,Button,Tk,Text,Frame


class SimpleGUI(Frame):
    def __init__(self,queue,parent=None,label=None,title=None,):
        Frame.__init__(self, parent)
        self.pack(expand="yes", fill="both")
        self.makewidgets(label)
        self.queue = queue
        self.checkandprint()

    def makewidgets(self,label):
        self.label = Label(self, text=label)
        self.label.pack()
        self.text_win = Text(self,height=40, width=150)
        self.text_win.config(state="disabled")
        self.text_win.config(bg='black')
        self.text_win.config(fg='green')
        self.text_win.config(font=('Courier',12))
        self.text_win.pack()

    def printtoscreen(self,message='text'):
        self.text_win.config(state="normal")
        self.text_win.insert("end",">>>%s\n"%message)
        self.text_win.see("end")
        self.text_win.update()
        self.text_win.config(state="disabled")

    def printerror(self,message):
        self.text_win.config(state="normal")
        self.text_win.config(fg='red')
        self.text_win.insert("end",">>>%s\n"%message)
        self.text_win.see("end")
        self.text_win.update()
        self.text_win.config(state="disabled")
        self.text_win.config(fg='green')

    def printtoline(self,message='text'):
        self.text_win.config(state="normal")
        self.text_win.delete('current linestart','end')
        self.text_win.insert("end",">>>%s"%message)
        self.text_win.see("end")
        self.text_win.update()
        self.text_win.config(state="disabled")

    def checkandprint(self):
        while True:
            if not self.queue.empty():
                self.printtoscreen(self.queue.get())
            #TODO implemention of error printing