mod terminal;

// rustdoc-stripper-ignore-next
/// Traits intended for blanket imports.
pub mod prelude {
    #[doc(hidden)]
    pub use gtk::subclass::prelude::*;

    pub use super::terminal::{TerminalImpl, TerminalImplExt};
}
