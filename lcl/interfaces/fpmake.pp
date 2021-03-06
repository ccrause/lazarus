{
   File generated automatically by Lazarus Package Manager

   fpmake.pp for LCL 2.1

   This file was generated on 31.12.2018
}

{$ifndef ALLPACKAGES} 
{$mode objfpc}{$H+}
program fpmake;

uses fpmkunit;
{$endif ALLPACKAGES}

procedure add_LCL(const ADirectory: string);

var
  P : TPackage;
  T : TTarget;

begin
  with Installer do
    begin
    P:=AddPackage('lcl');
    P.Version:='2.1';

    P.Directory:=ADirectory;

    P.Flags.Add('LazarusDsgnPkg');

    P.Dependencies.Add('lclbase');
    P.Options.Add('-MObjFPC');
    P.Options.Add('-Scghi');
    P.Options.Add('-O1');
    P.Options.Add('-g');
    P.Options.Add('-gl');
    P.Options.Add('-l');
    P.Options.Add('-vewnhibq');
    P.Options.Add('-vm5044');
    P.IncludePath.Add('$(LCLWidgetType)');
    P.UnitPath.Add('$(LCLWidgetType)');
    P.UnitPath.Add('.');
    T:=P.Targets.AddUnit('lcl.pas');
    t.Dependencies.AddUnit('agl');
    t.Dependencies.AddUnit('alllclintfunits');
    t.Dependencies.AddUnit('carbonbars');
    t.Dependencies.AddUnit('carbonbuttons');
    t.Dependencies.AddUnit('carboncalendar');
    t.Dependencies.AddUnit('carboncalendarview');
    t.Dependencies.AddUnit('carboncanvas');
    t.Dependencies.AddUnit('carboncaret');
    t.Dependencies.AddUnit('carbonclipboard');
    t.Dependencies.AddUnit('carbondbgconsts');
    t.Dependencies.AddUnit('carbondebug');
    t.Dependencies.AddUnit('carbondef');
    t.Dependencies.AddUnit('carbonedits');
    t.Dependencies.AddUnit('carbongdiobjects');
    t.Dependencies.AddUnit('carbonint');
    t.Dependencies.AddUnit('carbonlistviews');
    t.Dependencies.AddUnit('carbonmenus');
    t.Dependencies.AddUnit('carbonprivate');
    t.Dependencies.AddUnit('carbonproc');
    t.Dependencies.AddUnit('carbonstrings');
    t.Dependencies.AddUnit('carbontabs');
    t.Dependencies.AddUnit('carbonthemes');
    t.Dependencies.AddUnit('carbonutils');
    t.Dependencies.AddUnit('carbonwsbuttons');
    t.Dependencies.AddUnit('carbonwscalendar');
    t.Dependencies.AddUnit('carbonwschecklst');
    t.Dependencies.AddUnit('carbonwscomctrls');
    t.Dependencies.AddUnit('carbonwscontrols');
    t.Dependencies.AddUnit('carbonwsdialogs');
    t.Dependencies.AddUnit('carbonwsextctrls');
    t.Dependencies.AddUnit('carbonwsextdlgs');
    t.Dependencies.AddUnit('carbonwsfactory');
    t.Dependencies.AddUnit('carbonwsforms');
    t.Dependencies.AddUnit('carbonwsgrids');
    t.Dependencies.AddUnit('carbonwsimglist');
    t.Dependencies.AddUnit('carbonwsmenus');
    t.Dependencies.AddUnit('carbonwspairsplitter');
    t.Dependencies.AddUnit('carbonwsspin');
    t.Dependencies.AddUnit('carbonwsstdctrls');
    t.Dependencies.AddUnit('glgrab');
    t.Dependencies.AddUnit('interfaces');
    t.Dependencies.AddUnit('opengl');
    t.Dependencies.AddUnit('alllclintfunits');
    t.Dependencies.AddUnit('cocoagdiobjects');
    t.Dependencies.AddUnit('cocoaint');
    t.Dependencies.AddUnit('cocoaprivate');
    t.Dependencies.AddUnit('cocoautils');
    t.Dependencies.AddUnit('cocoawscommon');
    t.Dependencies.AddUnit('cocoawsextctrls');
    t.Dependencies.AddUnit('cocoawsfactory');
    t.Dependencies.AddUnit('cocoawsforms');
    t.Dependencies.AddUnit('cocoawsmenus');
    t.Dependencies.AddUnit('cocoawsstdctrls');
    t.Dependencies.AddUnit('interfaces');
    t.Dependencies.AddUnit('alllclintfunits');
    t.Dependencies.AddUnit('fpguiint');
    t.Dependencies.AddUnit('fpguiobjects');
    t.Dependencies.AddUnit('fpguiproc');
    t.Dependencies.AddUnit('fpguiwsbuttons');
    t.Dependencies.AddUnit('fpguiwscalendar');
    t.Dependencies.AddUnit('fpguiwscomctrls');
    t.Dependencies.AddUnit('fpguiwscontrols');
    t.Dependencies.AddUnit('fpguiwsdialogs');
    t.Dependencies.AddUnit('fpguiwsextctrls');
    t.Dependencies.AddUnit('fpguiwsextdlgs');
    t.Dependencies.AddUnit('fpguiwsfactory');
    t.Dependencies.AddUnit('fpguiwsforms');
    t.Dependencies.AddUnit('fpguiwsgrids');
    t.Dependencies.AddUnit('fpguiwsimglist');
    t.Dependencies.AddUnit('fpguiwsmenus');
    t.Dependencies.AddUnit('fpguiwspairsplitter');
    t.Dependencies.AddUnit('fpguiwsprivate');
    t.Dependencies.AddUnit('fpguiwsstdctrls');
    t.Dependencies.AddUnit('interfaces');
    t.Dependencies.AddUnit('alllclintfunits');
    t.Dependencies.AddUnit('gtk1def');
    t.Dependencies.AddUnit('gtk1int');
    t.Dependencies.AddUnit('gtk1wsprivate');
    t.Dependencies.AddUnit('gtkdebug');
    t.Dependencies.AddUnit('gtkdef');
    t.Dependencies.AddUnit('gtkextra');
    t.Dependencies.AddUnit('gtkfontcache');
    t.Dependencies.AddUnit('gtkglobals');
    t.Dependencies.AddUnit('gtkint');
    t.Dependencies.AddUnit('gtkmsgqueue');
    t.Dependencies.AddUnit('gtkproc');
    t.Dependencies.AddUnit('gtkthemes');
    t.Dependencies.AddUnit('gtkwinapiwindow');
    t.Dependencies.AddUnit('gtkwsbuttons');
    t.Dependencies.AddUnit('gtkwscalendar');
    t.Dependencies.AddUnit('gtkwschecklst');
    t.Dependencies.AddUnit('gtkwscomctrls');
    t.Dependencies.AddUnit('gtkwscontrols');
    t.Dependencies.AddUnit('gtkwsdialogs');
    t.Dependencies.AddUnit('gtkwsextctrls');
    t.Dependencies.AddUnit('gtkwsextdlgs');
    t.Dependencies.AddUnit('gtkwsfactory');
    t.Dependencies.AddUnit('gtkwsforms');
    t.Dependencies.AddUnit('gtkwsgrids');
    t.Dependencies.AddUnit('gtkwsimglist');
    t.Dependencies.AddUnit('gtkwsmenus');
    t.Dependencies.AddUnit('gtkwspairsplitter');
    t.Dependencies.AddUnit('gtkwsprivate');
    t.Dependencies.AddUnit('gtkwsspin');
    t.Dependencies.AddUnit('gtkwsstdctrls');
    t.Dependencies.AddUnit('interfaces');
    t.Dependencies.AddUnit('alllclintfunits');
    t.Dependencies.AddUnit('gtk2cellrenderer');
    t.Dependencies.AddUnit('gtk2debug');
    t.Dependencies.AddUnit('gtk2def');
    t.Dependencies.AddUnit('gtk2extra');
    t.Dependencies.AddUnit('gtk2fontcache');
    t.Dependencies.AddUnit('gtk2globals');
    t.Dependencies.AddUnit('gtk2int');
    t.Dependencies.AddUnit('gtk2listviewtreemodel');
    t.Dependencies.AddUnit('gtk2msgqueue');
    t.Dependencies.AddUnit('gtk2proc');
    t.Dependencies.AddUnit('gtk2themes');
    t.Dependencies.AddUnit('gtk2winapiwindow');
    t.Dependencies.AddUnit('gtk2windows');
    t.Dependencies.AddUnit('gtk2wsbuttons');
    t.Dependencies.AddUnit('gtk2wscalendar');
    t.Dependencies.AddUnit('gtk2wschecklst');
    t.Dependencies.AddUnit('gtk2wscomctrls');
    t.Dependencies.AddUnit('gtk2wscontrols');
    t.Dependencies.AddUnit('gtk2wsdialogs');
    t.Dependencies.AddUnit('gtk2wsextctrls');
    t.Dependencies.AddUnit('gtk2wsextdlgs');
    t.Dependencies.AddUnit('gtk2wsfactory');
    t.Dependencies.AddUnit('gtk2wsforms');
    t.Dependencies.AddUnit('gtk2wsgrids');
    t.Dependencies.AddUnit('gtk2wsimglist');
    t.Dependencies.AddUnit('gtk2wsmenus');
    t.Dependencies.AddUnit('gtk2wspairsplitter');
    t.Dependencies.AddUnit('gtk2wsprivate');
    t.Dependencies.AddUnit('gtk2wsspin');
    t.Dependencies.AddUnit('gtk2wsstdctrls');
    t.Dependencies.AddUnit('unitywsctrls');
    t.Dependencies.AddUnit('interfaces');
    t.Dependencies.AddUnit('alllclintfunits');
    t.Dependencies.AddUnit('interfaces');
    t.Dependencies.AddUnit('win32debug');
    t.Dependencies.AddUnit('win32def');
    t.Dependencies.AddUnit('win32extra');
    t.Dependencies.AddUnit('win32int');
    t.Dependencies.AddUnit('win32proc');
    t.Dependencies.AddUnit('win32themes');
    t.Dependencies.AddUnit('win32wsbuttons');
    t.Dependencies.AddUnit('win32wscalendar');
    t.Dependencies.AddUnit('win32wschecklst');
    t.Dependencies.AddUnit('win32wscomctrls');
    t.Dependencies.AddUnit('win32wscontrols');
    t.Dependencies.AddUnit('win32wsdialogs');
    t.Dependencies.AddUnit('win32wsextctrls');
    t.Dependencies.AddUnit('win32wsextdlgs');
    t.Dependencies.AddUnit('win32wsfactory');
    t.Dependencies.AddUnit('win32wsforms');
    t.Dependencies.AddUnit('win32wsgrids');
    t.Dependencies.AddUnit('win32wsimglist');
    t.Dependencies.AddUnit('win32wsmenus');
    t.Dependencies.AddUnit('win32wspairsplitter');
    t.Dependencies.AddUnit('win32wsshellctrls');
    t.Dependencies.AddUnit('win32wsspin');
    t.Dependencies.AddUnit('win32wsstdctrls');
    t.Dependencies.AddUnit('win32wstoolwin');
    t.Dependencies.AddUnit('interfaces');
    t.Dependencies.AddUnit('win32compat');
    t.Dependencies.AddUnit('wincedef');
    t.Dependencies.AddUnit('winceextra');
    t.Dependencies.AddUnit('winceint');
    t.Dependencies.AddUnit('winceproc');
    t.Dependencies.AddUnit('wincewsbuttons');
    t.Dependencies.AddUnit('wincewscalendar');
    t.Dependencies.AddUnit('wincewschecklst');
    t.Dependencies.AddUnit('wincewscomctrls');
    t.Dependencies.AddUnit('wincewscontrols');
    t.Dependencies.AddUnit('wincewsdialogs');
    t.Dependencies.AddUnit('wincewsextctrls');
    t.Dependencies.AddUnit('wincewsfactory');
    t.Dependencies.AddUnit('wincewsforms');
    t.Dependencies.AddUnit('wincewsgrids');
    t.Dependencies.AddUnit('wincewsimglist');
    t.Dependencies.AddUnit('wincewsmenus');
    t.Dependencies.AddUnit('wincewsspin');
    t.Dependencies.AddUnit('wincewsstdctrls');
    t.Dependencies.AddUnit('winext');
    t.Dependencies.AddUnit('alllclintfunits');
    t.Dependencies.AddUnit('alllclintfunits');
    t.Dependencies.AddUnit('interfaces');
    t.Dependencies.AddUnit('qt4');
    t.Dependencies.AddUnit('qt45');
    t.Dependencies.AddUnit('qtcaret');
    t.Dependencies.AddUnit('qtint');
    t.Dependencies.AddUnit('qtobjects');
    t.Dependencies.AddUnit('qtprivate');
    t.Dependencies.AddUnit('qtproc');
    t.Dependencies.AddUnit('qtthemes');
    t.Dependencies.AddUnit('qtwidgets');
    t.Dependencies.AddUnit('qtwsbuttons');
    t.Dependencies.AddUnit('qtwscalendar');
    t.Dependencies.AddUnit('qtwschecklst');
    t.Dependencies.AddUnit('qtwscomctrls');
    t.Dependencies.AddUnit('qtwscontrols');
    t.Dependencies.AddUnit('qtwsdesigner');
    t.Dependencies.AddUnit('qtwsdialogs');
    t.Dependencies.AddUnit('qtwsextctrls');
    t.Dependencies.AddUnit('qtwsextdlgs');
    t.Dependencies.AddUnit('qtwsfactory');
    t.Dependencies.AddUnit('qtwsforms');
    t.Dependencies.AddUnit('qtwsgrids');
    t.Dependencies.AddUnit('qtwsimglist');
    t.Dependencies.AddUnit('qtwsmenus');
    t.Dependencies.AddUnit('qtwspairsplitter');
    t.Dependencies.AddUnit('qtwsspin');
    t.Dependencies.AddUnit('qtwsstdctrls');
    t.Dependencies.AddUnit('cocoawsbuttons');
    t.Dependencies.AddUnit('customdrawn_winproc');
    t.Dependencies.AddUnit('alllclintfunits');
    t.Dependencies.AddUnit('customdrawnint');
    t.Dependencies.AddUnit('customdrawnwscontrols');
    t.Dependencies.AddUnit('customdrawnwsfactory');
    t.Dependencies.AddUnit('customdrawnwsforms');
    t.Dependencies.AddUnit('interfaces');
    t.Dependencies.AddUnit('cocoagdiobjects');
    t.Dependencies.AddUnit('customdrawn_cocoaproc');
    t.Dependencies.AddUnit('cocoautils');
    t.Dependencies.AddUnit('customdrawnproc');
    t.Dependencies.AddUnit('customdrawn_x11proc');
    t.Dependencies.AddUnit('customdrawn_androidproc');
    t.Dependencies.AddUnit('android_native_app_glue');
    t.Dependencies.AddUnit('asset_manager');
    t.Dependencies.AddUnit('configuration');
    t.Dependencies.AddUnit('egl');
    t.Dependencies.AddUnit('gles');
    t.Dependencies.AddUnit('input');
    t.Dependencies.AddUnit('jni');
    t.Dependencies.AddUnit('keycodes');
    t.Dependencies.AddUnit('log');
    t.Dependencies.AddUnit('looper');
    t.Dependencies.AddUnit('native_activity');
    t.Dependencies.AddUnit('native_window');
    t.Dependencies.AddUnit('rect');
    t.Dependencies.AddUnit('bitmap');
    t.Dependencies.AddUnit('customdrawnwsstdctrls');
    t.Dependencies.AddUnit('customdrawnwscomctrls');
    t.Dependencies.AddUnit('customdrawnwsextctrls');
    t.Dependencies.AddUnit('customdrawnprivate');
    t.Dependencies.AddUnit('cocoacaret');
    t.Dependencies.AddUnit('customdrawnwslazdeviceapis');
    t.Dependencies.AddUnit('alllclintfunits');
    t.Dependencies.AddUnit('interfaces');
    t.Dependencies.AddUnit('noguiint');
    t.Dependencies.AddUnit('noguiwsfactory');
    t.Dependencies.AddUnit('customdrawnwsspin');
    t.Dependencies.AddUnit('customdrawnwsbuttons');
    t.Dependencies.AddUnit('customdrawnwsdialogs');
    t.Dependencies.AddUnit('customdrawnwsmenus');
    t.Dependencies.AddUnit('gtk2disableliboverlay');
    t.Dependencies.AddUnit('gtk3int');
    t.Dependencies.AddUnit('interfaces');
    t.Dependencies.AddUnit('gtk3cellrenderer');
    t.Dependencies.AddUnit('gtk3objects');
    t.Dependencies.AddUnit('gtk3private');
    t.Dependencies.AddUnit('gtk3procs');
    t.Dependencies.AddUnit('gtk3widgets');
    t.Dependencies.AddUnit('gtk3wsbuttons');
    t.Dependencies.AddUnit('gtk3wschecklst');
    t.Dependencies.AddUnit('gtk3wscomctrls');
    t.Dependencies.AddUnit('gtk3wscontrols');
    t.Dependencies.AddUnit('gtk3wsextctrls');
    t.Dependencies.AddUnit('gtk3wsfactory');
    t.Dependencies.AddUnit('gtk3wsforms');
    t.Dependencies.AddUnit('gtk3wsimglist');
    t.Dependencies.AddUnit('gtk3wsmenus');
    t.Dependencies.AddUnit('gtk3wsspin');
    t.Dependencies.AddUnit('gtk3wsstdctrls');
    t.Dependencies.AddUnit('gtk3wscalendar');
    t.Dependencies.AddUnit('lazatk1');
    t.Dependencies.AddUnit('lazcairo1');
    t.Dependencies.AddUnit('lazgdk3');
    t.Dependencies.AddUnit('lazgdkpixbuf2');
    t.Dependencies.AddUnit('lazgio2');
    t.Dependencies.AddUnit('lazglib2');
    t.Dependencies.AddUnit('lazgmodule2');
    t.Dependencies.AddUnit('lazgobject2');
    t.Dependencies.AddUnit('lazgtk3');
    t.Dependencies.AddUnit('cocoawsdialogs');
    t.Dependencies.AddUnit('lazpango1');
    t.Dependencies.AddUnit('lazpangocairo1');
    t.Dependencies.AddUnit('cocoathemes');
    t.Dependencies.AddUnit('cocoawscomctrls');
    t.Dependencies.AddUnit('qtsystemtrayicon');
    t.Dependencies.AddUnit('gtk3wsdialogs');
    t.Dependencies.AddUnit('gtk3wsextdlgs');
    t.Dependencies.AddUnit('alllclintfunits');
    t.Dependencies.AddUnit('interfaces');
    t.Dependencies.AddUnit('qt5');
    t.Dependencies.AddUnit('qtcaret');
    t.Dependencies.AddUnit('qtint');
    t.Dependencies.AddUnit('qtobjects');
    t.Dependencies.AddUnit('qtprivate');
    t.Dependencies.AddUnit('qtproc');
    t.Dependencies.AddUnit('qtsystemtrayicon');
    t.Dependencies.AddUnit('qtthemes');
    t.Dependencies.AddUnit('qtwidgets');
    t.Dependencies.AddUnit('qtwsbuttons');
    t.Dependencies.AddUnit('qtwscalendar');
    t.Dependencies.AddUnit('qtwschecklst');
    t.Dependencies.AddUnit('qtwscomctrls');
    t.Dependencies.AddUnit('qtwscontrols');
    t.Dependencies.AddUnit('qtwsdesigner');
    t.Dependencies.AddUnit('qtwsdialogs');
    t.Dependencies.AddUnit('qtwsextctrls');
    t.Dependencies.AddUnit('qtwsextdlgs');
    t.Dependencies.AddUnit('qtwsfactory');
    t.Dependencies.AddUnit('qtwsforms');
    t.Dependencies.AddUnit('qtwsgrids');
    t.Dependencies.AddUnit('qtwsimglist');
    t.Dependencies.AddUnit('qtwsmenus');
    t.Dependencies.AddUnit('qtwspairsplitter');
    t.Dependencies.AddUnit('qtwsspin');
    t.Dependencies.AddUnit('qtwsstdctrls');
    t.Dependencies.AddUnit('cocoatabcontrols');
    t.Dependencies.AddUnit('cocoabuttons');
    t.Dependencies.AddUnit('cocoawindows');
    t.Dependencies.AddUnit('cocoatables');
    t.Dependencies.AddUnit('cocoatextedits');
    t.Dependencies.AddUnit('cocoascrollers');
    t.Dependencies.AddUnit('cocoawsclipboard');
    t.Dependencies.AddUnit('cocoawschecklst');
    t.Dependencies.AddUnit('cocoadatepicker');

    P.Targets.AddImplicitUnit('carbon/agl.pp');
    P.Targets.AddImplicitUnit('carbon/alllclintfunits.pas');
    P.Targets.AddImplicitUnit('carbon/carbonbars.pp');
    P.Targets.AddImplicitUnit('carbon/carbonbuttons.pp');
    P.Targets.AddImplicitUnit('carbon/carboncalendar.pas');
    P.Targets.AddImplicitUnit('carbon/carboncalendarview.pas');
    P.Targets.AddImplicitUnit('carbon/carboncanvas.pp');
    P.Targets.AddImplicitUnit('carbon/carboncaret.pas');
    P.Targets.AddImplicitUnit('carbon/carbonclipboard.pp');
    P.Targets.AddImplicitUnit('carbon/carbondbgconsts.pp');
    P.Targets.AddImplicitUnit('carbon/carbondebug.pp');
    P.Targets.AddImplicitUnit('carbon/carbondef.pp');
    P.Targets.AddImplicitUnit('carbon/carbonedits.pp');
    P.Targets.AddImplicitUnit('carbon/carbongdiobjects.pp');
    P.Targets.AddImplicitUnit('carbon/carbonint.pas');
    P.Targets.AddImplicitUnit('carbon/carbonlistviews.pp');
    P.Targets.AddImplicitUnit('carbon/carbonmenus.pp');
    P.Targets.AddImplicitUnit('carbon/carbonprivate.pp');
    P.Targets.AddImplicitUnit('carbon/carbonproc.pp');
    P.Targets.AddImplicitUnit('carbon/carbonstrings.pp');
    P.Targets.AddImplicitUnit('carbon/carbontabs.pp');
    P.Targets.AddImplicitUnit('carbon/carbonthemes.pas');
    P.Targets.AddImplicitUnit('carbon/carbonutils.pas');
    P.Targets.AddImplicitUnit('carbon/carbonwsbuttons.pp');
    P.Targets.AddImplicitUnit('carbon/carbonwscalendar.pp');
    P.Targets.AddImplicitUnit('carbon/carbonwschecklst.pp');
    P.Targets.AddImplicitUnit('carbon/carbonwscomctrls.pp');
    P.Targets.AddImplicitUnit('carbon/carbonwscontrols.pp');
    P.Targets.AddImplicitUnit('carbon/carbonwsdialogs.pp');
    P.Targets.AddImplicitUnit('carbon/carbonwsextctrls.pp');
    P.Targets.AddImplicitUnit('carbon/carbonwsextdlgs.pp');
    P.Targets.AddImplicitUnit('carbon/carbonwsfactory.pas');
    P.Targets.AddImplicitUnit('carbon/carbonwsforms.pp');
    P.Targets.AddImplicitUnit('carbon/carbonwsgrids.pp');
    P.Targets.AddImplicitUnit('carbon/carbonwsimglist.pp');
    P.Targets.AddImplicitUnit('carbon/carbonwsmenus.pp');
    P.Targets.AddImplicitUnit('carbon/carbonwspairsplitter.pp');
    P.Targets.AddImplicitUnit('carbon/carbonwsspin.pp');
    P.Targets.AddImplicitUnit('carbon/carbonwsstdctrls.pp');
    P.Targets.AddImplicitUnit('carbon/glgrab.pas');
    P.Targets.AddImplicitUnit('carbon/interfaces.pas');
    P.Targets.AddImplicitUnit('carbon/opengl.pas');
    P.Targets.AddImplicitUnit('cocoa/alllclintfunits.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoagdiobjects.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoaint.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoaprivate.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoautils.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoawscommon.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoawsextctrls.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoawsfactory.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoawsforms.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoawsmenus.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoawsstdctrls.pas');
    P.Targets.AddImplicitUnit('cocoa/interfaces.pas');
    P.Targets.AddImplicitUnit('fpgui/alllclintfunits.pas');
    P.Targets.AddImplicitUnit('fpgui/fpguiint.pp');
    P.Targets.AddImplicitUnit('fpgui/fpguiobjects.pas');
    P.Targets.AddImplicitUnit('fpgui/fpguiproc.pas');
    P.Targets.AddImplicitUnit('fpgui/fpguiwsbuttons.pp');
    P.Targets.AddImplicitUnit('fpgui/fpguiwscalendar.pp');
    P.Targets.AddImplicitUnit('fpgui/fpguiwscomctrls.pp');
    P.Targets.AddImplicitUnit('fpgui/fpguiwscontrols.pp');
    P.Targets.AddImplicitUnit('fpgui/fpguiwsdialogs.pp');
    P.Targets.AddImplicitUnit('fpgui/fpguiwsextctrls.pp');
    P.Targets.AddImplicitUnit('fpgui/fpguiwsextdlgs.pp');
    P.Targets.AddImplicitUnit('fpgui/fpguiwsfactory.pas');
    P.Targets.AddImplicitUnit('fpgui/fpguiwsforms.pp');
    P.Targets.AddImplicitUnit('fpgui/fpguiwsgrids.pp');
    P.Targets.AddImplicitUnit('fpgui/fpguiwsimglist.pp');
    P.Targets.AddImplicitUnit('fpgui/fpguiwsmenus.pp');
    P.Targets.AddImplicitUnit('fpgui/fpguiwspairsplitter.pp');
    P.Targets.AddImplicitUnit('fpgui/fpguiwsprivate.pp');
    P.Targets.AddImplicitUnit('fpgui/fpguiwsstdctrls.pp');
    P.Targets.AddImplicitUnit('fpgui/interfaces.pp');
    P.Targets.AddImplicitUnit('gtk/alllclintfunits.pas');
    P.Targets.AddImplicitUnit('gtk/gtk1def.pp');
    P.Targets.AddImplicitUnit('gtk/gtk1int.pp');
    P.Targets.AddImplicitUnit('gtk/gtk1wsprivate.pp');
    P.Targets.AddImplicitUnit('gtk/gtkdebug.pp');
    P.Targets.AddImplicitUnit('gtk/gtkdef.pp');
    P.Targets.AddImplicitUnit('gtk/gtkextra.pp');
    P.Targets.AddImplicitUnit('gtk/gtkfontcache.pas');
    P.Targets.AddImplicitUnit('gtk/gtkglobals.pp');
    P.Targets.AddImplicitUnit('gtk/gtkint.pp');
    P.Targets.AddImplicitUnit('gtk/gtkmsgqueue.pp');
    P.Targets.AddImplicitUnit('gtk/gtkproc.pp');
    P.Targets.AddImplicitUnit('gtk/gtkthemes.pas');
    P.Targets.AddImplicitUnit('gtk/gtkwinapiwindow.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwsbuttons.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwscalendar.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwschecklst.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwscomctrls.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwscontrols.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwsdialogs.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwsextctrls.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwsextdlgs.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwsfactory.pas');
    P.Targets.AddImplicitUnit('gtk/gtkwsforms.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwsgrids.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwsimglist.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwsmenus.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwspairsplitter.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwsprivate.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwsspin.pp');
    P.Targets.AddImplicitUnit('gtk/gtkwsstdctrls.pp');
    P.Targets.AddImplicitUnit('gtk/interfaces.pp');
    P.Targets.AddImplicitUnit('gtk2/alllclintfunits.pas');
    P.Targets.AddImplicitUnit('gtk2/gtk2cellrenderer.pas');
    P.Targets.AddImplicitUnit('gtk2/gtk2debug.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2def.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2extra.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2fontcache.pas');
    P.Targets.AddImplicitUnit('gtk2/gtk2globals.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2int.pas');
    P.Targets.AddImplicitUnit('gtk2/gtk2listviewtreemodel.pas');
    P.Targets.AddImplicitUnit('gtk2/gtk2msgqueue.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2proc.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2themes.pas');
    P.Targets.AddImplicitUnit('gtk2/gtk2winapiwindow.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2windows.pas');
    P.Targets.AddImplicitUnit('gtk2/gtk2wsbuttons.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wscalendar.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wschecklst.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wscomctrls.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wscontrols.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wsdialogs.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wsextctrls.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wsextdlgs.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wsfactory.pas');
    P.Targets.AddImplicitUnit('gtk2/gtk2wsforms.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wsgrids.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wsimglist.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wsmenus.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wspairsplitter.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wsprivate.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wsspin.pp');
    P.Targets.AddImplicitUnit('gtk2/gtk2wsstdctrls.pp');
    P.Targets.AddImplicitUnit('gtk2/unitywsctrls.pas');
    P.Targets.AddImplicitUnit('gtk2/interfaces.pas');
    P.Targets.AddImplicitUnit('win32/alllclintfunits.pas');
    P.Targets.AddImplicitUnit('win32/interfaces.pp');
    P.Targets.AddImplicitUnit('win32/win32debug.pp');
    P.Targets.AddImplicitUnit('win32/win32def.pp');
    P.Targets.AddImplicitUnit('win32/win32extra.pas');
    P.Targets.AddImplicitUnit('win32/win32int.pp');
    P.Targets.AddImplicitUnit('win32/win32proc.pp');
    P.Targets.AddImplicitUnit('win32/win32themes.pas');
    P.Targets.AddImplicitUnit('win32/win32wsbuttons.pp');
    P.Targets.AddImplicitUnit('win32/win32wscalendar.pp');
    P.Targets.AddImplicitUnit('win32/win32wschecklst.pp');
    P.Targets.AddImplicitUnit('win32/win32wscomctrls.pp');
    P.Targets.AddImplicitUnit('win32/win32wscontrols.pp');
    P.Targets.AddImplicitUnit('win32/win32wsdialogs.pp');
    P.Targets.AddImplicitUnit('win32/win32wsextctrls.pp');
    P.Targets.AddImplicitUnit('win32/win32wsextdlgs.pp');
    P.Targets.AddImplicitUnit('win32/win32wsfactory.pas');
    P.Targets.AddImplicitUnit('win32/win32wsforms.pp');
    P.Targets.AddImplicitUnit('win32/win32wsgrids.pp');
    P.Targets.AddImplicitUnit('win32/win32wsimglist.pp');
    P.Targets.AddImplicitUnit('win32/win32wsmenus.pp');
    P.Targets.AddImplicitUnit('win32/win32wspairsplitter.pp');
    P.Targets.AddImplicitUnit('win32/win32wsspin.pp');
    P.Targets.AddImplicitUnit('win32/win32wsshellctrls.pp');
    P.Targets.AddImplicitUnit('win32/win32wsstdctrls.pp');
    P.Targets.AddImplicitUnit('win32/win32wstoolwin.pp');
    P.Targets.AddImplicitUnit('wince/interfaces.pp');
    P.Targets.AddImplicitUnit('wince/win32compat.pas');
    P.Targets.AddImplicitUnit('wince/wincedef.pp');
    P.Targets.AddImplicitUnit('wince/winceextra.pp');
    P.Targets.AddImplicitUnit('wince/winceint.pp');
    P.Targets.AddImplicitUnit('wince/winceproc.pp');
    P.Targets.AddImplicitUnit('wince/wincewsbuttons.pp');
    P.Targets.AddImplicitUnit('wince/wincewscalendar.pp');
    P.Targets.AddImplicitUnit('wince/wincewschecklst.pp');
    P.Targets.AddImplicitUnit('wince/wincewscomctrls.pp');
    P.Targets.AddImplicitUnit('wince/wincewscontrols.pp');
    P.Targets.AddImplicitUnit('wince/wincewsdialogs.pp');
    P.Targets.AddImplicitUnit('wince/wincewsextctrls.pp');
    P.Targets.AddImplicitUnit('wince/wincewsfactory.pas');
    P.Targets.AddImplicitUnit('wince/wincewsforms.pp');
    P.Targets.AddImplicitUnit('wince/wincewsgrids.pp');
    P.Targets.AddImplicitUnit('wince/wincewsimglist.pp');
    P.Targets.AddImplicitUnit('wince/wincewsmenus.pp');
    P.Targets.AddImplicitUnit('wince/wincewsspin.pp');
    P.Targets.AddImplicitUnit('wince/wincewsstdctrls.pp');
    P.Targets.AddImplicitUnit('wince/winext.pas');
    P.Targets.AddImplicitUnit('wince/alllclintfunits.pas');
    P.Targets.AddImplicitUnit('qt/alllclintfunits.pas');
    P.Targets.AddImplicitUnit('qt/interfaces.pp');
    P.Targets.AddImplicitUnit('qt/qt4.pas');
    P.Targets.AddImplicitUnit('qt/qt45.pas');
    P.Targets.AddImplicitUnit('qt/qtcaret.pas');
    P.Targets.AddImplicitUnit('qt/qtint.pp');
    P.Targets.AddImplicitUnit('qt/qtobjects.pas');
    P.Targets.AddImplicitUnit('qt/qtprivate.pp');
    P.Targets.AddImplicitUnit('qt/qtproc.pp');
    P.Targets.AddImplicitUnit('qt/qtthemes.pas');
    P.Targets.AddImplicitUnit('qt/qtwidgets.pas');
    P.Targets.AddImplicitUnit('qt/qtwsbuttons.pp');
    P.Targets.AddImplicitUnit('qt/qtwscalendar.pp');
    P.Targets.AddImplicitUnit('qt/qtwschecklst.pp');
    P.Targets.AddImplicitUnit('qt/qtwscomctrls.pp');
    P.Targets.AddImplicitUnit('qt/qtwscontrols.pp');
    P.Targets.AddImplicitUnit('qt/qtwsdesigner.pp');
    P.Targets.AddImplicitUnit('qt/qtwsdialogs.pp');
    P.Targets.AddImplicitUnit('qt/qtwsextctrls.pp');
    P.Targets.AddImplicitUnit('qt/qtwsextdlgs.pp');
    P.Targets.AddImplicitUnit('qt/qtwsfactory.pas');
    P.Targets.AddImplicitUnit('qt/qtwsforms.pp');
    P.Targets.AddImplicitUnit('qt/qtwsgrids.pp');
    P.Targets.AddImplicitUnit('qt/qtwsimglist.pp');
    P.Targets.AddImplicitUnit('qt/qtwsmenus.pp');
    P.Targets.AddImplicitUnit('qt/qtwspairsplitter.pp');
    P.Targets.AddImplicitUnit('qt/qtwsspin.pp');
    P.Targets.AddImplicitUnit('qt/qtwsstdctrls.pp');
    P.Targets.AddImplicitUnit('cocoa/cocoawsbuttons.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawn_winproc.pas');
    T:=P.Targets.AddUnit('customdrawn/alllclintfunits.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawnint.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawnwscontrols.pp');
    P.Targets.AddImplicitUnit('customdrawn/customdrawnwsfactory.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawnwsforms.pp');
    P.Targets.AddImplicitUnit('customdrawn/interfaces.pas');
    P.Targets.AddImplicitUnit('customdrawn/cocoagdiobjects.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawn_cocoaproc.pas');
    P.Targets.AddImplicitUnit('customdrawn/cocoautils.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawnproc.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawn_x11proc.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawn_androidproc.pas');
    P.Targets.AddImplicitUnit('customdrawn/android/android_native_app_glue.pas');
    P.Targets.AddImplicitUnit('customdrawn/android/asset_manager.pas');
    P.Targets.AddImplicitUnit('customdrawn/android/configuration.pas');
    P.Targets.AddImplicitUnit('customdrawn/android/egl.pas');
    P.Targets.AddImplicitUnit('customdrawn/android/gles.pas');
    P.Targets.AddImplicitUnit('customdrawn/android/input.pas');
    P.Targets.AddImplicitUnit('customdrawn/android/jni.pas');
    P.Targets.AddImplicitUnit('customdrawn/android/keycodes.pas');
    P.Targets.AddImplicitUnit('customdrawn/android/log.pas');
    P.Targets.AddImplicitUnit('customdrawn/android/looper.pas');
    P.Targets.AddImplicitUnit('customdrawn/android/native_activity.pas');
    P.Targets.AddImplicitUnit('customdrawn/android/native_window.pas');
    P.Targets.AddImplicitUnit('customdrawn/android/rect.pas');
    P.Targets.AddImplicitUnit('customdrawn/android/bitmap.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawnwsstdctrls.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawnwscomctrls.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawnwsextctrls.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawnprivate.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoacaret.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawnwslazdeviceapis.pas');
    P.Targets.AddImplicitUnit('nogui/alllclintfunits.pas');
    P.Targets.AddImplicitUnit('nogui/interfaces.pp');
    P.Targets.AddImplicitUnit('nogui/noguiint.pp');
    P.Targets.AddImplicitUnit('nogui/noguiwsfactory.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawnwsspin.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawnwsbuttons.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawnwsdialogs.pas');
    P.Targets.AddImplicitUnit('customdrawn/customdrawnwsmenus.pas');
    P.Targets.AddImplicitUnit('gtk2/gtk2disableliboverlay.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3int.pas');
    P.Targets.AddImplicitUnit('gtk3/interfaces.pp');
    P.Targets.AddImplicitUnit('gtk3/gtk3cellrenderer.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3objects.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3private.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3procs.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3widgets.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3wsbuttons.pp');
    P.Targets.AddImplicitUnit('gtk3/gtk3wschecklst.pp');
    P.Targets.AddImplicitUnit('gtk3/gtk3wscomctrls.pp');
    P.Targets.AddImplicitUnit('gtk3/gtk3wscontrols.pp');
    P.Targets.AddImplicitUnit('gtk3/gtk3wsextctrls.pp');
    P.Targets.AddImplicitUnit('gtk3/gtk3wsfactory.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3wsforms.pp');
    P.Targets.AddImplicitUnit('gtk3/gtk3wsimglist.pp');
    P.Targets.AddImplicitUnit('gtk3/gtk3wsmenus.pp');
    P.Targets.AddImplicitUnit('gtk3/gtk3wsspin.pp');
    P.Targets.AddImplicitUnit('gtk3/gtk3wsstdctrls.pp');
    P.Targets.AddImplicitUnit('gtk3/gtk3wscalendar.pp');
    P.Targets.AddImplicitUnit('gtk3/gtk3bindings/lazatk1.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3bindings/lazcairo1.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3bindings/lazgdk3.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3bindings/lazgdkpixbuf2.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3bindings/lazgio2.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3bindings/lazglib2.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3bindings/lazgmodule2.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3bindings/lazgobject2.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3bindings/lazgtk3.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoawsdialogs.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3bindings/lazpango1.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3bindings/lazpangocairo1.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoathemes.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoawscomctrls.pas');
    P.Targets.AddImplicitUnit('qt/qtsystemtrayicon.pas');
    P.Targets.AddImplicitUnit('gtk3/gtk3wsdialogs.pp');
    P.Targets.AddImplicitUnit('gtk3/gtk3wsextdlgs.pp');
    P.Targets.AddImplicitUnit('qt5/alllclintfunits.pas');
    P.Targets.AddImplicitUnit('qt5/interfaces.pp');
    P.Targets.AddImplicitUnit('qt5/qt5.pas');
    P.Targets.AddImplicitUnit('qt5/qtcaret.pas');
    P.Targets.AddImplicitUnit('qt5/qtint.pp');
    P.Targets.AddImplicitUnit('qt5/qtobjects.pas');
    P.Targets.AddImplicitUnit('qt5/qtprivate.pp');
    P.Targets.AddImplicitUnit('qt5/qtproc.pp');
    P.Targets.AddImplicitUnit('qt5/qtsystemtrayicon.pas');
    P.Targets.AddImplicitUnit('qt5/qtthemes.pas');
    P.Targets.AddImplicitUnit('qt5/qtwidgets.pas');
    P.Targets.AddImplicitUnit('qt5/qtwsbuttons.pp');
    P.Targets.AddImplicitUnit('qt5/qtwscalendar.pp');
    P.Targets.AddImplicitUnit('qt5/qtwschecklst.pp');
    P.Targets.AddImplicitUnit('qt5/qtwscomctrls.pp');
    P.Targets.AddImplicitUnit('qt5/qtwscontrols.pp');
    P.Targets.AddImplicitUnit('qt5/qtwsdesigner.pp');
    P.Targets.AddImplicitUnit('qt5/qtwsdialogs.pp');
    P.Targets.AddImplicitUnit('qt5/qtwsextctrls.pp');
    P.Targets.AddImplicitUnit('qt5/qtwsextdlgs.pp');
    P.Targets.AddImplicitUnit('qt5/qtwsfactory.pas');
    P.Targets.AddImplicitUnit('qt5/qtwsforms.pp');
    P.Targets.AddImplicitUnit('qt5/qtwsgrids.pp');
    P.Targets.AddImplicitUnit('qt5/qtwsimglist.pp');
    P.Targets.AddImplicitUnit('qt5/qtwsmenus.pp');
    P.Targets.AddImplicitUnit('qt5/qtwspairsplitter.pp');
    P.Targets.AddImplicitUnit('qt5/qtwsspin.pp');
    P.Targets.AddImplicitUnit('qt5/qtwsstdctrls.pp');
    P.Targets.AddImplicitUnit('cocoa/cocoatabcontrols.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoabuttons.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoawindows.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoatables.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoatextedits.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoascrollers.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoawsclipboard.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoawschecklst.pas');
    P.Targets.AddImplicitUnit('cocoa/cocoadatepicker.pas');

    // copy the compiled file, so the IDE knows how the package was compiled
    P.InstallFiles.Add('LCL.compiled',AllOSes,'$(unitinstalldir)');

    end;
end;

{$ifndef ALLPACKAGES}
begin
  add_LCL('');
  Installer.Run;
end.
{$endif ALLPACKAGES}
