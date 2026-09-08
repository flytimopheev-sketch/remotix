// Take a look at the license at the top of the repository in the LICENSE file.

// rustdoc-stripper-ignore-next
//! Traits intended for subclassing [`Terminal`](crate::Terminal).

use glib::translate::*;
/*
pub struct VteTerminalClass {
    pub commit: Option<unsafe extern "C" fn(*mut VteTerminal, *const c_char, c_uint)>,
}
*/
use crate::{ffi, prelude::*, subclass::prelude::*, Terminal};

pub trait TerminalImpl: TerminalImplExt + WidgetImpl {
    fn commit(&self, text: &str) {
        self.parent_commit(text)
    }

    fn move_window(&self, x: u32, y: u32) {
        self.parent_move_window(x, y)
    }

    fn resize_window(&self, columns: u32, rows: u32) {
        self.parent_resize_window(columns, rows)
    }

    fn child_exited(&self, status: i32) {
        self.parent_child_exited(status)
    }

    fn char_size_changed(&self, width: u32, height: u32) {
        self.parent_char_size_changed(width, height)
    }

    fn eof(&self) {
        self.parent_eof()
    }

    fn encoding_changed(&self) {
        self.parent_encoding_changed();
    }

    fn window_title_changed(&self) {
        self.parent_window_title_changed();
    }

    fn icon_title_changed(&self) {
        self.parent_icon_title_changed();
    }

    fn selection_changed(&self) {
        self.parent_selection_changed();
    }

    fn contents_changed(&self) {
        self.parent_contents_changed();
    }

    fn cursor_moved(&self) {
        self.parent_cursor_moved();
    }

    fn deiconify_window(&self) {
        self.parent_deiconify_window();
    }

    fn iconify_window(&self) {
        self.parent_iconify_window();
    }

    fn raise_window(&self) {
        self.parent_raise_window();
    }

    fn lower_window(&self) {
        self.parent_lower_window();
    }

    fn refresh_window(&self) {
        self.parent_refresh_window();
    }

    fn restore_window(&self) {
        self.parent_restore_window();
    }

    fn maximize_window(&self) {
        self.parent_maximize_window();
    }

    fn increase_font_size(&self) {
        self.parent_increase_font_size();
    }

    fn decrease_font_size(&self) {
        self.parent_decrease_font_size();
    }

    fn copy_clipboard(&self) {
        self.parent_copy_clipboard();
    }

    fn paste_clipboard(&self) {
        self.parent_paste_clipboard();
    }

    fn bell(&self) {
        self.parent_bell();
    }
}

mod sealed {
    pub trait Sealed {}
    impl<T: super::TerminalImplExt> Sealed for T {}
}

pub trait TerminalImplExt: sealed::Sealed + ObjectSubclass {
    fn parent_commit(&self, text: &str) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).commit {
                f(
                    self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0,
                    text.to_glib_none().0,
                    text.len() as _,
                )
            }
        }
    }

    fn parent_move_window(&self, x: u32, y: u32) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).move_window {
                f(
                    self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0,
                    x,
                    y,
                )
            }
        }
    }

    fn parent_resize_window(&self, columns: u32, rows: u32) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).resize_window {
                f(
                    self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0,
                    columns,
                    rows,
                )
            }
        }
    }

    fn parent_child_exited(&self, status: i32) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).child_exited {
                f(
                    self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0,
                    status,
                )
            }
        }
    }

    fn parent_char_size_changed(&self, width: u32, height: u32) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).char_size_changed {
                f(
                    self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0,
                    width,
                    height,
                )
            }
        }
    }

    fn parent_eof(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).eof {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }

    fn parent_encoding_changed(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).encoding_changed {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_window_title_changed(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).window_title_changed {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_icon_title_changed(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).icon_title_changed {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_selection_changed(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).selection_changed {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_contents_changed(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).contents_changed {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_cursor_moved(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).cursor_moved {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_deiconify_window(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).deiconify_window {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_iconify_window(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).iconify_window {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_raise_window(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).raise_window {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_lower_window(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).lower_window {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_refresh_window(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).refresh_window {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_restore_window(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).restore_window {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_maximize_window(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).maximize_window {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_increase_font_size(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).increase_font_size {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_decrease_font_size(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).decrease_font_size {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_copy_clipboard(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).copy_clipboard {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_paste_clipboard(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).paste_clipboard {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
    fn parent_bell(&self) {
        unsafe {
            let data = Self::type_data();
            let parent_class = data.as_ref().parent_class() as *mut ffi::VteTerminalClass;
            if let Some(f) = (*parent_class).bell {
                f(self.obj().unsafe_cast_ref::<Terminal>().to_glib_none().0)
            }
        }
    }
}
impl<T: TerminalImpl> TerminalImplExt for T {}

unsafe impl<T: TerminalImpl> IsSubclassable<T> for Terminal {
    fn class_init(class: &mut glib::Class<Self>) {
        Self::parent_class_init::<T>(class);

        let klass = class.as_mut();
        klass.commit = Some(terminal_commit::<T>);
        klass.move_window = Some(terminal_move_window::<T>);
        klass.resize_window = Some(terminal_resize_window::<T>);
        klass.char_size_changed = Some(terminal_char_size_changed::<T>);
        klass.child_exited = Some(terminal_child_exited::<T>);
        klass.eof = Some(terminal_eof::<T>);
        klass.encoding_changed = Some(terminal_encoding_changed::<T>);
        klass.window_title_changed = Some(terminal_window_title_changed::<T>);
        klass.icon_title_changed = Some(terminal_icon_title_changed::<T>);
        klass.selection_changed = Some(terminal_selection_changed::<T>);
        klass.contents_changed = Some(terminal_contents_changed::<T>);
        klass.cursor_moved = Some(terminal_cursor_moved::<T>);
        klass.deiconify_window = Some(terminal_deiconify_window::<T>);
        klass.iconify_window = Some(terminal_iconify_window::<T>);
        klass.raise_window = Some(terminal_raise_window::<T>);
        klass.lower_window = Some(terminal_lower_window::<T>);
        klass.refresh_window = Some(terminal_refresh_window::<T>);
        klass.restore_window = Some(terminal_restore_window::<T>);
        klass.maximize_window = Some(terminal_maximize_window::<T>);
        klass.increase_font_size = Some(terminal_increase_font_size::<T>);
        klass.decrease_font_size = Some(terminal_decrease_font_size::<T>);
        klass.copy_clipboard = Some(terminal_copy_clipboard::<T>);
        klass.paste_clipboard = Some(terminal_paste_clipboard::<T>);
        klass.bell = Some(terminal_bell::<T>);
    }
}

unsafe extern "C" fn terminal_commit<T: TerminalImpl>(
    ptr: *mut ffi::VteTerminal,
    textptr: *const std::ffi::c_char,
    length: u32,
) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();

    imp.commit(&glib::GString::from_ptr_and_len_unchecked(
        textptr,
        length as _,
    ))
}

unsafe extern "C" fn terminal_child_exited<T: TerminalImpl>(
    ptr: *mut ffi::VteTerminal,
    status: i32,
) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();

    imp.child_exited(status)
}

unsafe extern "C" fn terminal_move_window<T: TerminalImpl>(
    ptr: *mut ffi::VteTerminal,
    x: u32,
    y: u32,
) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();

    imp.move_window(x, y)
}

unsafe extern "C" fn terminal_resize_window<T: TerminalImpl>(
    ptr: *mut ffi::VteTerminal,
    columns: u32,
    rows: u32,
) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();

    imp.resize_window(columns, rows)
}

unsafe extern "C" fn terminal_char_size_changed<T: TerminalImpl>(
    ptr: *mut ffi::VteTerminal,
    width: u32,
    height: u32,
) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();

    imp.char_size_changed(width, height)
}

unsafe extern "C" fn terminal_eof<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();

    imp.eof()
}

unsafe extern "C" fn terminal_encoding_changed<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.encoding_changed()
}

unsafe extern "C" fn terminal_window_title_changed<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.window_title_changed()
}

unsafe extern "C" fn terminal_icon_title_changed<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.icon_title_changed()
}

unsafe extern "C" fn terminal_selection_changed<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.selection_changed()
}

unsafe extern "C" fn terminal_contents_changed<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.contents_changed()
}

unsafe extern "C" fn terminal_cursor_moved<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.cursor_moved()
}

unsafe extern "C" fn terminal_deiconify_window<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.deiconify_window()
}

unsafe extern "C" fn terminal_iconify_window<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.iconify_window()
}

unsafe extern "C" fn terminal_raise_window<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.raise_window()
}

unsafe extern "C" fn terminal_lower_window<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.lower_window()
}

unsafe extern "C" fn terminal_refresh_window<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.refresh_window()
}

unsafe extern "C" fn terminal_restore_window<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.restore_window()
}

unsafe extern "C" fn terminal_maximize_window<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.maximize_window()
}

unsafe extern "C" fn terminal_increase_font_size<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.increase_font_size()
}

unsafe extern "C" fn terminal_decrease_font_size<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.decrease_font_size()
}

unsafe extern "C" fn terminal_copy_clipboard<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.copy_clipboard()
}

unsafe extern "C" fn terminal_paste_clipboard<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.paste_clipboard()
}

unsafe extern "C" fn terminal_bell<T: TerminalImpl>(ptr: *mut ffi::VteTerminal) {
    let instance = &*(ptr as *mut T::Instance);
    let imp = instance.imp();
    imp.bell()
}
