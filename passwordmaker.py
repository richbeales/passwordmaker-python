#!/usr/bin/env python
# coding: utf-8
"""
  PasswordMaker - Creates and manages passwords
  Copyright (C) 2005 Eric H. Jung and LeahScape, Inc.
  http://passwordmaker.org/
  grimholtz@yahoo.com

  This library is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or (at
  your option) any later version.

  This library is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
  for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this library; if not, write to the Free Software Foundation,
  Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

  Written by Miquel Burns and Eric H. Jung

  PHP version written by Pedro Gimeno Fortea
      <http://www.formauri.es/personal/pgimeno/>
  and updated by Miquel Matthew 'Fire' Burns
      <miquelfire@gmail.com>
  Ported to Python by Aurelien Bompard
      <http://aurelien.bompard.org>
  Updated by Richard Beales
      <rich@richbeales.net>

  This version should work with python > 2.3. The pycrypto module enables
  additional algorithms.

  Can be used both on the command-line and with a GUI based on TKinter
"""
import sys
import optparse

import attr

from pwmlib import PWM, PWM_Settings, PWM_Error

try:
    import tkinter as tk
except ImportError:
    tk = None


class Entry(tk.Entry):
    """Entry widget that binds it self to a setting"""

    def __init__(self, parent, setting_name, *args, **kwargs):
        self.background = parent.background
        self.settings = parent.settings
        self.setting_name = setting_name
        self.type_converter = self._get_type_converter()

        tk.Entry.__init__(self, parent, *args, **kwargs)

        self.bind("<Key>", self.evaluate)
        self.bind("<BackSpace>", self.evaluate)

    def _get_type_converter(self):
        """Determines target type from validator"""

        a = attr.fields(PWM_Settings).__getattribute__(self.setting_name)
        validator = a.validator
        if validator == PWM_Settings.str_val:
            return str
        elif validator == PWM_Settings.int_val:
            return int
        elif validator == PWM_Settings.bool_val:
            return bool
        else:
            raise TypeError("Unknown validator type {}.".format(validator))

    def evaluate(self, event):
        if event.keycode == 22:  # Backspace
            val = event.widget.get()[:-1]
        elif event.keycode == 23:  # Tab
            val = event.widget.get()
        else:
            val = event.widget.get() + event.char
        try:
            cval = self.type_converter(val)
            self.settings.__setattr__(self.setting_name, cval)
            self.config(background=self.background)
        except ValueError:
            self.config(background="red")


class Application(tk.Frame):

    def __init__(self, root=None):
        self.root = root
        self.PWmaker = PWM()
        tk.Frame.__init__(self, root)
        self.background = root.cget("background")

        self.settings = PWM_Settings()

        self.create_widgets()
        self.layout()

    def create_widgets(self):

        # Widgets

        self.labels = []
        self.entry_widgets = []

        for setting in attr.fields(PWM_Settings):
            self.labels.append(tk.Label(self, justify="left",
                                        text=setting.metadata["guitext"]))

            if setting.name == "MasterPass":
                self.entry_widgets.append(Entry(self, setting.name, show="*"))
                val = self.settings.__getattribute__(setting.name)
                self.entry_widgets[-1].insert(0, val)

            elif setting.name == "Algorithm":
                alg = tk.StringVar(self)
                alg.set(self.settings.Algorithm)
                valid_algs = tuple(self.PWmaker.valid_algs)
                self.entry_widgets.append(tk.OptionMenu(self, alg,
                                                        *valid_algs))
            elif setting.name == "Length":
                self.entry_widgets.append(tk.Spinbox(self, from_=1, to=128))
                self.entry_widgets[-1].delete(0, "end")
                self.entry_widgets[-1].insert(0, self.settings.Length)
            else:
                self.entry_widgets.append(Entry(self, setting.name))
                val = self.settings.__getattribute__(setting.name)
                self.entry_widgets[-1].insert(0, val)

        # Buttons

        self.generate_button = tk.Button(self, text="Generate",
                                         command=self.generate)
        self.load_button = tk.Button(self, text="Load", command=self.load)
        self.save_button = tk.Button(self, text="Save", command=self.save)
        self.passwd_label = tk.Label(self, justify="left", text="Password")
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

        self.generate_button.grid(row=i+1, column=1, columnspan=2, pady=5, sticky="nsew")
        self.load_button.grid(row=i+2, column=1, columnspan=1, pady=5, sticky="we")
        self.save_button.grid(row=i+2, column=2, columnspan=1, pady=5, sticky="we")
        self.passwd_label.grid(row=i+3, column=0)
        self.passwd_text.grid(row=i+3, column=1, columnspan=2, sticky="nsew")

    def save(self):
        self.settings = self.getsettings()
        self.settings.MasterPass = ''  # Blank this out when saving for now
        self.settings.save()

    def load(self):
        self.settings = self.getsettings()
        self.settings.load()
        self.createWidgets()

    def generate(self):
        self.generate_button.flash()
        try:
            pw = self.PWmaker.generatepasswordfrom(self.settings)
        except PWM_Error as e:
            pw = str(e)
        current_passwd = self.passwd_text.get()
        if len(current_passwd) > 0:
            self.passwd_text.delete(0, len(current_passwd))
        self.passwd_text.insert(0, pw)
        self.clipboard_clear()
        self.clipboard_append(pw)


def gui():
    root = tk.Tk()
    app = Application(root=root)
    app.master.title("PasswordMaker")
    app.mainloop()


def cmd():
    usage = "Usage: %prog [options]"
    settings = PWM_Settings()
    settings.load()
    parser = optparse.OptionParser(usage=usage)

    for setting in attr.fields(PWM_Settings):
        cmd1 = setting.metadata["cmd1"]
        cmd2 = setting.metadata["cmd2"]
        dest = setting.name
        default = setting.default
        __help = setting.metadata["help"]
        parser.add_option(cmd1, cmd2, dest=dest, default=default, help=__help)

    options, args = parser.parse_args()
    if options.MasterPass == "":
        import getpass
        options.MasterPass = getpass.getpass("Master password: ")

    PWmaker = PWM()

    gen_pwd = PWmaker.generatepassword
    print(gen_pwd(options.Algorithm,
                  options.MasterPass,
                  options.URL + options.Username + options.Modifier,
                  options.UseLeet,
                  options.LeetLvl - 1,
                  options.Length,
                  options.CharacterSet,
                  options.Prefix,
                  options.Suffix,
                  ))


# Main
if __name__ == "__main__":
    if len(sys.argv) == 1:
        gui()
    else:
        cmd()
