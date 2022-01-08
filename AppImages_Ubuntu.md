# AppImages are distributables, that can be used to run applications on Linux Machines. Think it of as an executable. 

So lets see how app images are installed.

### Using an AppImage in Ubuntu/ Linux

- Prepare the executable from AppImage
```bash
chmod a+x example.AppImage
```

- Run the AppImage
```bash
./example.AppImage
```

- Run the executable by heading over to Application Menu (bottom left on Ubuntu) and search for the name and click on the name of the AppImage. 

### How to Delete the AppImage
Usually, if you see, AppImages can be uninstalled by removing the AppImage File itself. 
<br/>
But you need to delete the memory entry of AppImage. 

This is done by:
- Going to `$Home` dir in your Linux Machine
- Press `Ctrl+H` ( if on GUI) or use `ls -a` to show all kind of files ( including hidden
- Head over to directory `$HOME/.local/share/applications`.
- Find the `example.AppImage` in the directory and delete it.
- Checkout your Applications Menu, to cross-verify the application is deleted.
