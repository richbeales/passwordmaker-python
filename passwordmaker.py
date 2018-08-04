#!/usr/bin/env python
# coding=utf-8

"""

PasswordMaker - Python
======================

Create and manage passwords.


Copyright (C):

    2005      Eric H. Jung, Miquel Burns and LeahScape, Inc.
              <http://passwordmaker.org>
              <grimholtz@yahoo.com>
    2005-2007 Pedro Gimeno Fortea and Miquel Matthew 'Fire' Burns
              <http://www.formauri.es/personal/pgimeno/>
              <miquelfire@gmail.com>
    2010      Aurelien Bompard
              <http://aurelien.bompard.org>
    2012      Richard Beales
              <rich@richbeales.net>
    2014      Richard Beales, Laurent Bachelier and Christoph Sarnowski
              <rich@richbeales.net>
    2018      Martin Manns
              <mmanns@gmx.net>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.


    This version should work with Python > 2.3 including Python 3.x.
    The pycrypto module enables additional algorithms.

    It can be used both on the command-line and with a GUI based on TKinter.

"""


import argparse
import sys

try:
    import tkinter as tk
    from tkinter import simpledialog, messagebox
except ImportError:
    tk = None

import attr

from pwmlib import ALGORITHMS
from pwmlib import generatepasswordfrom, PwmSettingsList, PwmSettings


class TextWidget(tk.Entry, object):
    """Text entry widget

    Interfaces: get, set

    """

    def set(self, value):
        """Sets current text"""

        self.delete(0, "end")
        self.insert(0, value)


class PasswordWidget(TextWidget):
    """Password entry widget

    Interfaces: get, set

    """

    def __init__(self, parent, *args, **kwargs):
        kwargs.update({'show': "*"})

        super(PasswordWidget, self).__init__(parent, *args, **kwargs)


class IntWidget(tk.Spinbox, object):
    """Spinbox widget for Integers

    Interfaces: get, set

    """

    def __init__(self, parent, *args, **kwargs):
        kwargs.update({'from_': 1, "to": 128})
        super(IntWidget, self).__init__(parent, *args, **kwargs)

    def get(self):
        return int(super(IntWidget, self).get())

    def set(self, value):
        """Sets current text"""

        self.delete(0, "end")
        self.insert(0, value)


class AlgorithmWidget(tk.OptionMenu, object):
    """OptionMenu widget for Algorithms

    Interfaces: get, set

    """

    def __init__(self, parent):
        self.alg = tk.StringVar(parent)
        super(AlgorithmWidget, self).__init__(parent, self.alg, "",
                                              *ALGORITHMS)

    def get(self):
        """Returns the current algorithm as string"""

        return self.alg.get()

    def set(self, value):
        """Sets current algorithm"""

        assert value in ALGORITHMS
        self.alg.set(value)


class Application(tk.Frame):
    """Main application window class"""

    type2widget = {
        "str": TextWidget,
        "pwd": PasswordWidget,
        "int": IntWidget,
        "alg": AlgorithmWidget,
    }

    def __init__(self, root=None):
        self.root = root
        tk.Frame.__init__(self, root)
        self.background = root.cget("background")

        self.settings_list = PwmSettingsList()
        self.settings = self.settings_list.get_pwm_settings()

        self.create_widgets()
        self.layout()

        self.load()

    def create_widgets(self):
        """Creates all widgets in main window"""

        # Entry widgets

        self.labels = []
        self.entry_widgets = []

        for setting in attr.fields(PwmSettings):
            self.labels.append(tk.Label(self, justify="left",
                                        text=setting.metadata["guitext"]))

            widget = self.type2widget[setting.type](self)
            widget.set(self.settings[setting.name])
            self.entry_widgets.append(widget)

        # Buttons

        self.generate_button = tk.Button(self, text="Generate",
                                         command=self.generate)
        self.load_button = tk.Button(self, text="Load", command=self.load)
        self.save_button = tk.Button(self, text="Save", command=self.save)
        self.passwd_label = tk.Label(self, justify="left", text="Password")
        self.listbox_label = tk.Label(self, justify="left", text="Settings")
        self.listbox = tk.Listbox(self)
        self.listbox .bind('<<ListboxSelect>>', self.on_listbox)
        self.listbox.insert("end", "default")
        self.listbox.select_set(0)
        self.new_setting_button = tk.Button(self, text="+",
                                            command=self.new_setting)
        self.delete_setting_button = tk.Button(self, text="-",
                                               command=self.del_setting)

        self.passwd_text = tk.Entry(self, fg="blue")

    def layout(self):
        """Places widgets on the grid"""

        self.grid(sticky="nsew")
        self.top = self.root.winfo_toplevel()
        self.top.rowconfigure(0, weight=1)
        self.top.columnconfigure(0, weight=1)
        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=1)

        for i, label in enumerate(self.labels):
            label.grid(row=i, column=0, sticky="w", padx=5, pady=2)

        for i, entry_widget in enumerate(self.entry_widgets):
            entry_widget.grid(row=i, column=1, columnspan=2, sticky="we")

        self.rowconfigure(i+1, weight=1)

        self.generate_button.grid(row=i+1, column=1, columnspan=2, pady=5,
                                  sticky="nsew")
        self.load_button.grid(row=i+2, column=1, columnspan=1, pady=5,
                              sticky="we")
        self.save_button.grid(row=i+2, column=2, columnspan=1, pady=5,
                              sticky="we")
        self.listbox_label.grid(row=i+3, column=0, sticky="nw", padx=5, pady=2)
        self.listbox.grid(row=i+3, rowspan=3, column=1, columnspan=2,
                          sticky="nsew")
        self.new_setting_button.grid(row=i+4, column=0, sticky="n", padx=5,
                                     pady=2)
        self.delete_setting_button.grid(row=i+5, column=0, sticky="n",
                                        padx=5, pady=2)
        self.passwd_label.grid(row=i+6, column=0, sticky="w", padx=5, pady=2)
        self.passwd_text.grid(row=i+6, column=1, columnspan=2, sticky="nsew")

    def update_settings(self):
        """Updates self.settings from entry widget values"""

        attr_fields = attr.fields(PwmSettings)
        for setting, widget in zip(attr_fields, self.entry_widgets):
            self.settings.__setattr__(setting.name, widget.get())

    def update_widgets(self):
        """Updates widgets from current self.settings"""

        self.settings = self.settings_list.get_pwm_settings()

        for setting, widget in zip(attr.fields(PwmSettings),
                                   self.entry_widgets):
            widget.set(self.settings[setting.name])

    def update_listbox(self):
        """Updates listbox from self.settings_list"""

        self.listbox.delete(0, "end")
        for pwm_name in self.settings_list.pwm_names:
            self.listbox.insert("end", pwm_name)
            self.listbox.select_set(0)

    def save(self):
        """Saves settings to json file"""

        self.update_settings()
        self.settings_list.save()

    def load(self):
        """Loads settings from json file"""

        self.settings_list.load()

        self.update_listbox()
        self.update_widgets()

    def on_listbox(self, event):
        self.update_settings()

        widget = event.widget
        if not widget.curselection():
            # Empty cell
            return
        index = int(widget.curselection()[0])
        value = widget.get(index)

        self.settings_list.current = value
        self.update_widgets()

    def new_setting(self):
        """Adds pwm setting to self.settings_list"""

        name = None
        while name is None or not name or name in self.settings_list.pwm_names:
            name = simpledialog.askstring("Create new settings set", "Name")
            if name is None:
                return

        self.settings_list.pwm_names.append(name)
        self.settings_list.pwms.append(PwmSettings())

        self.update_listbox()

    def del_setting(self):
        """deletes setting from listbox and fromk settings_list"""

        index = int(self.listbox.curselection()[0])
        value = self.listbox.get(index)
        if value == "default":
            return

        # Check if the setting is intentionally being deleted
        msgbox = messagebox.askyesno
        if not msgbox("Delete setting",
                      "Do you want to permanently delete the setting?"):
            return

        pwm_idx = self.settings_list.pwm_names.index(value)
        self.settings_list.pwm_names.pop(pwm_idx)
        self.settings_list.pwms.pop(pwm_idx)
        if self.settings_list.current == value:
            self.settings_list.current = "default"

        self.listbox.delete(index)
        self.listbox.select_set(0)

    def generate(self):
        """Generates and prints password and copies it to the clipboard"""

        self.update_settings()
        self.generate_button.flash()

        pwd = generatepasswordfrom(self.settings)

        current_passwd = self.passwd_text.get()
        if current_passwd:
            self.passwd_text.delete(0, len(current_passwd))
        self.passwd_text.insert(0, pwd)
        self.clipboard_clear()
        self.clipboard_append(pwd)


def gui():
    """Run application in GUI"""

    root = tk.Tk()
    app = Application(root=root)
    app.master.title("PasswordMaker")
    app.mainloop()


def cmd():
    """Run application in the command line"""

    def get_parser():
        """Returns command line argument parser"""

        description = "Usage: %prog [options]"
        parser = argparse.ArgumentParser(description=description)

        for setting in attr.fields(PwmSettings):
            cmd1 = setting.metadata["cmd1"]
            cmd2 = setting.metadata["cmd2"]
            dest = setting.name
            default = setting.default
            __help = setting.metadata["help"]
            parser.add_argument(cmd1, cmd2, dest=dest, default=default,
                                help=__help)
        return parser

    def update_settings(options, settings):
        """Updates self.settings from entry widget values"""

        for setting in attr.fields(PwmSettings):
            val = getattr(options, setting.name)
            if setting.name == "URL":
                val += options.Username + options.Modifier
            if setting.name in ("LeetLvl", "Length"):
                val = int(val)
            if setting.name == "LeetLvl":
                val -= 1
            settings.__setattr__(setting.name, val)

    parser = get_parser()
    args = parser.parse_args()

    args = parser.parse_args()

    if args.MasterPass == "":
        import getpass
        args.MasterPass = getpass.getpass("Master password: ")

    settings = PwmSettings()
    update_settings(args, settings)

    print(generatepasswordfrom(settings))


def main():
    """Main application that chooses between gui and non gui execution"""

    if len(sys.argv) == 1:
        gui()
    else:
        cmd()


# Main
if __name__ == "__main__":
    main()
