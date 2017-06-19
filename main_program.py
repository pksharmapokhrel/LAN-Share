import asyncio
from tkinter import *
import json
from tkinter import filedialog
from tkinter import messagebox
import os
import socket

node_no = 1
node_f = {}
LANG = ['DIRL', 'GETF', 'GET', 'PUS', 'RSM', 'CNL']
SERVER_ADDRESS = ('0.0.0.0', 8000)
AVAILABLE_NODES = dict()
NODE_DIRECTORIES = dict()
DIRECTORY_LIST = dict()
with open('config.json', 'r+') as f:
    my_details = json.load(f)
full_dir = my_details["directory"]
for i in my_details["directory"].keys():
    DIRECTORY_LIST.update({i: my_details["directory"][i][1]})
USERNAME = my_details["node"]["name"]
if my_details["node"]["DOWN_LOC"] == "":
    DOWN_LOC = ""
elif my_details["node"]["DOWN_LOC"][-1:] == "/":
    DOWN_LOC = my_details["node"]["DOWN_LOC"]
else:
    DOWN_LOC = my_details["node"]["DOWN_LOC"] + "/"
IP = None
GETVAR = False
INFO = {}
DOWNLOAD = {}
DOWNLOAD_FLAG = {}
DOWNLOAD_FLAG_S = {}


class OptFrame(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.pack(fill=X)
        self.create_widgets()
        self.config(borderwidth=1, relief=SUNKEN)

    def create_widgets(self):
        """Create the base widgets for the frame."""

root = Tk()
root.title("LAN Share 0.0")
root.resizable(0, 0)
container = Frame(root)
container.pack(fill="both")
with open('config.json', 'r+')as fq:
    data = json.load(fq)
p = data["node"]
if USERNAME == "":
    USERNAME = "unkown_001"

Label(container, text="Username :", font="10px").grid(row=0, column=0, padx=10)
username_lbl = Label(container, text=USERNAME, fg="blue", font="10px")
username_lbl.grid(row=0, column=1, padx=10)
Label(container, text="IP Address :", fg="black", font="10px").grid(row=0, column=2, padx=10)
ip_label = Label(container, text=p["IP address"], fg="blue", font="10px")
ip_label.grid(row=0, column=3, padx=10)
frames = {}
canvas_frame = {}
top_frame = None
username_lbl.update_idletasks()


def exit_check():
    if  len(DOWNLOAD_FLAG) >= 1:
        x = messagebox.askyesno("Are you Sure.", "Downloads are ongoing. Do you want to exit?")
        if x:
            root.destroy()
        else:
            pass

root.protocol("WM_DELETE_WINDOW", exit_check)


def show_frame(cls):
    frames[cls].tkraise()
    global top_frame
    top_frame = cls
    """for i in frames["NodeFrame"].frame.winfo_children():
        i.destroy()"""
    if cls == "SharedFrame":
        showDir()


def add_node(u_name, ip, shared):
    global node_no
    node_f.update({u_name: node_no})
    b = Button(canvas_frame["HomeFrame"], text=u_name + "\n" + ip)
    b.pack(side=LEFT, padx=10, pady=10)  # grid(row=self.row, column=column, sticky=E+W,)
    b.bind('<Double-Button-1>',
           lambda event, a=shared, add=(u_name, ip): browse_user(event, a, add))
    node_no = node_no + 1


def remove_node(u_name):
    global node_no
    pos = node_f[u_name]
    canvas_frame["HomeFrame"].winfo_children()[pos-1].destroy()
    j = 1
    del node_f[u_name]
    for i in node_f.keys():
        node_f.update({i: j})
        j = j + 1
    node_no = node_no - 1
    if top_frame == "NodeFrame":
        show_frame("HomeFrame")

node_frame_ip = None


def browse_user(event, shared, add):
    global node_frame_ip
    for i in canvas_frame["NodeFrame"].winfo_children():
        i.destroy()
    ip = add[1]
    frames["NodeFrame"].config(text="Shared Files of " + add[0].upper())
    show_frame("NodeFrame")
    node_frame_ip =add[1]
    for ir in shared.keys():
        print(ir)
        opt = OptFrame(canvas_frame["NodeFrame"])
        btn = Button(opt, text="DOWNLOAD", padx=10, command=lambda a=ir, b=shared[ir], c=ip: download(a, b, c))
        btn.pack(side=RIGHT, fill="x")
        Label(opt, text=ir + "\n" + str(shared[ir]), width=50, justify=LEFT).pack(side=LEFT, fill="x")


def pause_download(event, file, pbtn, rbtn):
    DOWNLOAD_FLAG[file][0] = 1
    pbtn.config(state=DISABLED)
    rbtn.config(state=NORMAL)


def resume_download(event, file, progress, pbtn, rbtn):
    ip = DOWNLOAD[file]["ip"]
    status = DOWNLOAD[file]["status"]
    size = DOWNLOAD[file]["size"]
    DOWNLOAD.update({file: {"size": size, "status": "0", "ip": ip}})
    DOWNLOAD_FLAG.update({file: [0, ip]})
    pbtn.config(state=NORMAL)
    rbtn.config(state=DISABLED)
    return asyncio.ensure_future(tcp_echo_client(["RESUME", status], file, size, ip, progress))


def add_download(file, size, f_ram):
    opt = OptFrame(f_ram)
    mb = (size / 1024) / 1024
    Label(opt, text=str(file) + "\n" + str(mb) + " MB", justify=LEFT).pack(fill="x")
    progress = Label(opt, text="")
    progress.pack(fill=X)
    opt1 = OptFrame(opt)
    if f_ram == downloading_frame:
        pbtn = Button(opt1, text="PAUSE")
        pbtn.pack(side=LEFT, padx=5)
        rbtn = Button(opt1, text="RESUME", state=DISABLED)
        rbtn.pack(side=LEFT, padx=5)
        pbtn.bind('<Button-1>', lambda event, a=file, b=pbtn, c=rbtn: pause_download(event, a, b, c))
        rbtn.bind('<Button-1>', lambda event, a=file, b=progress, c=pbtn, d=rbtn: resume_download(event, a, b, c, d))
    else:
        Label(opt1, text="DOWNLOAD COMPLETED").pack(fill=X)
    return progress


def download(file, size, ip):
    show_frame("DownloadFrame")
    fs = 0
    for iss in DOWNLOAD.keys():
        print(iss, DOWNLOAD[iss]["ip"])
        print(file, ip)
        if iss == file and DOWNLOAD[iss]["ip"] == ip:
            fs = 1
            print("conflict")
    if fs == 1:
        messagebox.showinfo("Download Info", "File is already added to your downloads")
    else:
        progress = add_download(file, size, downloading_frame)
        DOWNLOAD.update({file: {"size": size, "status": "0", "ip": ip}})
        DOWNLOAD_FLAG.update({file: [0, ip]})
        return asyncio.ensure_future(tcp_echo_client(["DOWNLOAD", 0], file, size, ip, progress))

for f in ("HomeFrame", "SharedFrame", "DownloadFrame", "SettingsFrame", "NodeFrame"):  # defined subclasses of BaseFrame
    frame = LabelFrame(container)
    name = f
    frame.grid(row=2, column=0, columnspan=4, sticky=N + S + E + W)
    frames[name] = frame
for f in frames.keys():
    def on_frame_configure(canvas):
        '''Reset the scroll region to encompass the inner frame'''
        canvas.configure(scrollregion=canvas.bbox("all"))

    canvas_r = Canvas(frames[f], borderwidth=1, relief=SUNKEN)
    frame = Frame(canvas_r, borderwidth=1, relief=SUNKEN)
    y_scrollbar = Scrollbar(frames[f], orient="vertical", command=canvas_r.yview)
    canvas_r.configure(yscrollcommand=y_scrollbar.set)
    y_scrollbar.pack(side="right", fill="y")
    canvas_r.pack(side="left", fill="both", expand=True)
    frame.pack(side="left", fill="y", expand=False)
    canvas_r.create_window(4, 4, window=frame, anchor="nw")
    frame.bind("<Configure>", lambda event, canvas=canvas_r: on_frame_configure(canvas))
    canvas_frame[f] = frame
show_frame("HomeFrame")
Button(container, text="Home", command=lambda: show_frame("HomeFrame")).grid(row=1, column=0,
                                                                             sticky=E + W)
Button(container, text="Shared", command=lambda: show_frame("SharedFrame")).grid(row=1, column=1,
                                                                                 sticky=E + W)
Button(container, text="Settings", command=lambda: show_frame("SettingsFrame")).grid(row=1, column=2,
                                                                                     sticky=E + W)
Button(container, text="Downloads", command=lambda: show_frame("DownloadFrame")).grid(row=1, column=3,
                                                                              sticky=E + W)
downloading_frame = OptFrame(canvas_frame["DownloadFrame"])
downloading_frame.pack(side=TOP)
downloaded_frame = OptFrame(canvas_frame["DownloadFrame"])
downloaded_frame.pack(side=BOTTOM)


def change_location():
    global DOWN_LOC
    cl = ""
    try:
        cl = filedialog.askdirectory()
    except:
        pass
    if cl == "":
        cl = DOWN_LOC
    with open("config.json", "r") as loc:
        my_data = json.load(loc)
    my_data["node"]["DOWN_LOC"] = cl
    with open("config.json", "w") as rit:
        json.dump(my_data, rit)
    down_loc_lbl.config(text=cl)
    DOWN_LOC = cl


def save_username():
    global USERNAME
    user = username_entry.get()
    if user == "":
        messagebox.showinfo("Change Username", "Please enter a username")
        username_entry.insert(0, USERNAME)
    elif user == USERNAME:
        messagebox.showinfo("Change Username", "Please enter a different username")
    else:
        x = messagebox.askyesno("Change Username", "Are you sure you want to change your username?")
        if x:
            with open("config.json", "r") as ab:
                data_s = json.load(ab)
            data_s["node"]["name"] = user
            with open("config.json", "w") as ab:
                json.dump(data_s, ab)
            USERNAME = user
            username_lbl.config(text=USERNAME)
        else:
            pass

o1 = OptFrame(canvas_frame["SettingsFrame"])
username_entry = Entry(o1)
username_entry.insert(0, USERNAME)
username_entry.grid(row=1, column=2, columnspan=2, sticky=E+W)
Button(o1, text="Change Username", command=save_username).grid(row=1, column=4, columnspan=2, sticky=E+W)
down_loc_lbl = Label(o1, text=DOWN_LOC)
down_loc_lbl.grid(row=2, column=2, columnspan=2, sticky=E+W)
down_loc_lbl.update_idletasks()
Button(o1, text="Change Location", command=change_location).grid(row=2, column=4, columnspan=2, sticky=E+W)



def addDir():
    x = filedialog.askopenfilename()
    path, name = x.rsplit('/', 1)
    st = os.stat(x)
    size = st.st_size
    if name in DIRECTORY_LIST.keys() and DIRECTORY_LIST[name] == size:
        print("File already Added.")
    else:
        with open('config.json', 'r') as f:
            my_detail = json.load(f)
            my_detail["directory"].update({name: [path, size]})
        with open('config.json', 'w') as f:
            json.dump(my_detail, f)
        DIRECTORY_LIST.update({name: size})
        broadcast_server.broadcast("ULIST:#:"+str(DIRECTORY_LIST))
        showDir()

def remove_f(name):
    with open("config.json", "r") as f:
        jb = json.load(f)
    del jb["directory"][name]
    with open("config.json", "w") as f:
        json.dump(jb, f)
    del DIRECTORY_LIST[name]
    showDir()
def showDir():
    for i in canvas_frame["SharedFrame"].winfo_children():
        i.destroy()
    row = 1
    for i in DIRECTORY_LIST.keys():
        Label(canvas_frame["SharedFrame"], text=i).grid(row=row, column=0, columnspan=3, sticky=W)
        Label(canvas_frame["SharedFrame"], text=str((DIRECTORY_LIST[i] / 1024) / 1024) + "MB").grid(row=row, column=3, sticky=W)
        Button(canvas_frame["SharedFrame"], text="X", fg="white", bg="black", command=lambda: remove_f(i)).grid(row=row, column=4, sticky=W)
        row = row + 1
    Button(canvas_frame["SharedFrame"], text="ADD FILE", command=addDir).grid(row=row, column=2)


async def run_tk(root, interval=0.05):
    '''
    Run a tkinter app in an asyncio event loop.
    '''
    try:
        while True:
            root.update()
            await asyncio.sleep(interval)
    except TclError as e:
        if "application has been destroyed" not in e.args[0]:
            raise


async def handle_client(reader, writer):
    address = writer.get_extra_info('peername')
    print('Client accepted :', address)
    data = await reader.read(128)
    print('received {!r}'.format(data))
    data = data.decode()
    data_unpacked = data.split("$$$$")
    if data_unpacked[0] == "GETF":
        DOWNLOAD_FLAG_S.update({data_unpacked[1]: [0, address[0]]})
        file_name_path = full_dir[data_unpacked[1]][0] + "/" + data_unpacked[1]
        file = open(file_name_path, 'rb')
        data = file.read(1024)
        g = 0
        while data:
            writer.write(data)
            if DOWNLOAD_FLAG_S[data_unpacked[1]][0] == 1:
                del DOWNLOAD_FLAG_S[data_unpacked[1]]
            g = g + 1024
            try:
                await writer.drain()
            except ConnectionResetError:
                break
            data = file.read(1024)
        file.close()
        await writer.drain()
        print('Done Sending..')
        del DOWNLOAD_FLAG_S[data_unpacked[1]]
        writer.close()
    if data_unpacked[0] == "STOP":
        for i in DOWNLOAD_FLAG_S.keys():
            if i == data_unpacked[1] and DOWNLOAD_FLAG_S[i][1] == address[0]:
                DOWNLOAD_FLAG_S.update({i: [1, address[0]]})
        writer.close()
    if data_unpacked[0] == "RESUME":
        DOWNLOAD_FLAG_S.update({data_unpacked[1]: [0, address[0]]})
        file_name_path = full_dir[data_unpacked[1]][0] + "/" + data_unpacked[1]
        file = open(file_name_path, 'rb')
        pos = int(data_unpacked[2])
        file.seek(pos)
        data = file.read(1024)
        g = 0
        while data:
            writer.write(data)
            if DOWNLOAD_FLAG_S[data_unpacked[1]][0] == 1:
                del DOWNLOAD_FLAG_S[data_unpacked[1]]
            g = g + 1024
            await writer.drain()
            data = file.read(1024)
        file.close()
        await writer.drain()
        print('Done Sending..')
        del DOWNLOAD_FLAG_S[data_unpacked[1]]
        writer.close()

async def tcp_echo_client(command, file, size, dest_ip, progress):
    reader, writer = await asyncio.open_connection(dest_ip, 8000)
    if command[0] == "DOWNLOAD":
        rq = 'GETF$$$$'+file
        writer.write(rq.encode())
        path_file = DOWN_LOC + file
        f1 = open(path_file, 'wb')
        total = 0
        while reader and writer:
            data = await reader.read(1024)
            total = total + len(data)
            f1.write(data)
            p = (total * 100) / size
            if DOWNLOAD_FLAG[file][0] == 1:
                r = f1.tell()
                print(r)
                DOWNLOAD.update({file: {"size": size, "status": str(total), "ip": dest_ip}})
                print(DOWNLOAD, DOWNLOAD_FLAG)
                await tcp_echo_client("STOP", file, size, dest_ip, progress)
                del DOWNLOAD_FLAG[file]
                break
            if total == size:
                progress.config(text="Downloading Completed")
                DOWNLOAD.update({file: {"size": size, "status": "complete", "ip": dest_ip}})
                del DOWNLOAD_FLAG[file]
                break
            progress.config(text="Downloading PROGRESS : "+str(round(p, 2))+"%")
        f1.close()
        writer.close()
        print('Downloading Complete')
    elif command[0] == "STOP":
        writer.write(("STOP$$$$"+file).encode())
        writer.close()
    elif command[0] == "RESUME":
        comnd = int(command[1])
        rq = "RESUME$$$$"+file+"$$$$"+str(comnd)
        writer.write(rq.encode())
        path_file = DOWN_LOC + file
        f1 = open(path_file, 'ab')
        total = int(command[1])
        while reader and writer:
            data = await reader.read(1024)
            total = total + len(data)
            f1.write(data)
            p = (total * 100) / size
            if DOWNLOAD_FLAG[file][0] == 1:
                DOWNLOAD.update({file: {"size": size, "status": str(total), "ip": dest_ip}})
                await tcp_echo_client("STOP", file, size, dest_ip, progress)
                del DOWNLOAD_FLAG[file]
                break
            if total == size:
                progress.config(text="Downloading Completed")
                DOWNLOAD.update({file: {"size": size, "status": "complete", "ip": dest_ip}})
                del DOWNLOAD_FLAG[file]
                break
            progress.config(text="Downloading PROGRESS : " + str(round(p, 2)) + "%")
        f1.close()
        writer.close()
        print('Downloading Complete')


class BroadcastProtocol:
    def __init__(self, loop, md):
        self.loop = loop
        self.mydetails = md
        self.LANG = ['IOPEN', 'ROPEN', 'DLIST', 'RLIST', 'CLOSE']

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.broadcast('IOPEN#:#'+self.mydetails)

    def datagram_received(self, data, addr):
        try:
            lang, value = data.decode().split('#:#')
            print(data)
            if value != self.mydetails:
                if lang == self.LANG[0]:
                    AVAILABLE_NODES.update({addr[0]: value})
                    self.transport.sendto(('ROPEN#:#'+self.mydetails).encode(), addr)
                elif lang == self.LANG[1]:
                    if addr[0] not in AVAILABLE_NODES.keys():
                        AVAILABLE_NODES.update({addr[0]: value})
                    self.transport.sendto(("DLIST#:#"+str(DIRECTORY_LIST)).encode(), addr)
                    print("Directory send")
                elif lang == self.LANG[2]:
                    NODE_DIRECTORIES.update({addr[0]: value})
                    self.transport.sendto(("RLIST#:#" + str(DIRECTORY_LIST)).encode(), addr)
                    print("Directory reply send")
                    directory = eval(value)
                    add_node(AVAILABLE_NODES[addr[0]], addr[0], directory)
                elif lang == self.LANG[3]:
                    directory = eval(value)
                    NODE_DIRECTORIES.update({addr[0]: value})
                    add_node(AVAILABLE_NODES[addr[0]], addr[0], directory)
                elif lang == self.LANG[4]:
                    print(AVAILABLE_NODES)
                    if addr[0] in AVAILABLE_NODES.keys():
                        remove_node(AVAILABLE_NODES[str(addr[0])])
                        del AVAILABLE_NODES[addr[0]]
                elif lang == "ULIST":
                    dir_s = eval(value)
                    NODE_DIRECTORIES.update({addr[0]: dir_s})
                    if top_frame == "NodeFrame" and node_frame_ip == addr[0]:
                        e = 0
                        browse_user(e, addr[0], dir_s)
            else:
                with open('config.json', 'r+')as fq:
                    data_r = json.load(fq)
                data_r["node"]["IP address"] = addr[0]
                with open('config.json', 'w') as fs:
                    json.dump(data_r, fs)
                ip_label.config(text=addr[0])
                global IP
                IP = addr[0]
        except ValueError:
            print('Received Datagram is useless..')

    def stop(self):
        self.broadcast('CLOSE#:#'+self.mydetails)
        print('Closing Broadcasting.')
        self.transport.close()

    def connection_lost(self, exc):
        print('broadcast server connection lost.')

    def broadcast(self, msg):
        print('broadcasting : ', msg)
        self.transport.sendto(msg.encode(), ('<broadcast>', 9000))

broadcast_server = BroadcastProtocol(asyncio.get_event_loop(), USERNAME)
async def main():
    coro = asyncio.get_event_loop().create_datagram_endpoint(lambda: broadcast_server, local_addr=('0.0.0.0', 9000))

    def server():
        while True:
            if IP is None:
                pass
            else:
                server_addr = (IP, 8000)
                factory = asyncio.start_server(handle_client, *server_addr)
                print("Server Startrd at.." + repr(server_addr))
                return asyncio.ensure_future(factory)
    await asyncio.ensure_future(coro)
    asyncio.get_event_loop().call_soon(server)
    await run_tk(root)
    broadcast_server.stop()


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
