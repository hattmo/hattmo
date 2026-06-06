#![feature(allocator_api)]
use std::{
    alloc::{AllocError, Allocator, Layout},
    ptr::NonNull,
    sync::Mutex,
};

pub struct Arena<const SIZE: usize> {
    space: [u8; SIZE],
    index: Mutex<usize>,
}

impl<const SIZE: usize> Default for Arena<SIZE> {
    fn default() -> Self {
        Self {
            space: [0; SIZE],
            index: Default::default(),
        }
    }
}

unsafe impl<const SIZE: usize> Allocator for &Arena<SIZE> {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let mut index = self.index.lock().or(Err(AllocError))?;
        let align = layout.align();
        let size = layout.size();
        let start = NonNull::from_ref(&self.space[*index]);
        let off = start.align_offset(align);
        if (*index + off + size) >= self.space.len() {
            return Err(AllocError);
        };
        *index += off + size;
        let start = unsafe { start.add(off) };
        let out = NonNull::slice_from_raw_parts(start, size);
        Ok(out)
    }

    unsafe fn deallocate(&self, _ptr: NonNull<u8>, _layout: Layout) {}
}

#[cfg(test)]
mod test {
    use crate::Arena;

    #[test]
    #[should_panic]
    fn test_allocator() {
        let arena: Arena<256> = Arena::default();
        loop {
            let _ = Box::try_new_in(56, &arena).unwrap();
        }
    }
}
