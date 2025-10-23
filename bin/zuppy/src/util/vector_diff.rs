use eyeball_im::VectorDiff;

pub trait VectorDiffApplicator<T> {
    fn apply_to_vec(self, vec: &mut Vec<T>);
}

impl<T> VectorDiffApplicator<T> for VectorDiff<T>
where
    T: Clone,
{
    fn apply_to_vec(self, vec: &mut Vec<T>) {
        match self {
            VectorDiff::Append { values } => {
                for i in values.into_iter() {
                    vec.push(i);
                }
            }
            VectorDiff::Clear => {
                vec.clear();
            }
            VectorDiff::PushFront { value } => {
                vec.insert(0, value);
            }
            VectorDiff::PushBack { value } => {
                vec.push(value);
            }
            VectorDiff::PopFront => {
                if !vec.is_empty() {
                    vec.remove(0);
                }
            }
            VectorDiff::PopBack => {
                vec.pop();
            }
            VectorDiff::Insert { index, value } => {
                vec.insert(index, value);
            }
            VectorDiff::Set { index, value } => {
                vec[index] = value;
            }
            VectorDiff::Remove { index } => {
                vec.remove(index);
            }
            VectorDiff::Truncate { length } => {
                vec.truncate(length);
            }
            VectorDiff::Reset { values } => {
                vec.clear();
                for i in values.into_iter() {
                    vec.push(i);
                }
            }
        }
    }
}
