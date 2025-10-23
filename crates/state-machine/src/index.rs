use std::ops::Deref;

use eyeball_im::{ObservableVector, ObservableVectorTransactionEntry, VectorDiff};
use futures::{Stream, StreamExt};

/// Keeps an index of items sorted by the given rank, highest rank first
pub struct RankedIndex<K, T>
where
    K: 'static + Ord + Clone,
    T: 'static + Clone + Eq,
{
    vector: ObservableVector<(K, T)>,
}
impl<K, T> Default for RankedIndex<K, T>
where
    K: 'static + Ord + Clone,
    T: 'static + Clone + Eq,
{
    fn default() -> Self {
        Self {
            vector: Default::default(),
        }
    }
}
impl<K, T> FromIterator<(K, T)> for RankedIndex<K, T>
where
    K: 'static + Ord + Clone,
    T: 'static + Clone + Eq,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (K, T)>,
    {
        let mut m = RankedIndex::default();
        // I feel like I should use a more efficient way to insert items
        for (rank, value) in iter {
            m.insert(rank, value);
        }
        m
    }
}

impl<K, T> Deref for RankedIndex<K, T>
where
    K: 'static + Ord + Clone,
    T: 'static + Clone + Eq,
{
    type Target = ObservableVector<(K, T)>;

    fn deref(&self) -> &Self::Target {
        &self.vector
    }
}

impl<K, T> RankedIndex<K, T>
where
    K: 'static + Ord + Clone,
    T: 'static + Clone + Eq,
{
    pub fn new_with(rank: K, value: T) -> Self {
        let mut m = RankedIndex::default();
        m.insert(rank, value);
        m
    }
    /// Insert the value T at the position of rank
    ///
    /// Will add at first position if a value of the same rank is found
    pub fn insert(&mut self, rank: K, value: T) {
        let mut pos = self.vector.len();
        for (idx, (k, _v)) in self.vector.iter().enumerate() {
            if k <= &rank {
                pos = idx;
                break;
            }
        }
        self.vector.insert(pos, (rank, value));
    }

    pub fn remove_and_insert(&mut self, pred: impl Fn(&T) -> bool, rank: K, value: T) {
        let mut t = self.vector.transaction();
        {
            // remove old
            let mut entries = t.entries();
            while let Some(entry) = entries.next() {
                if pred(&entry.1) {
                    ObservableVectorTransactionEntry::remove(entry);
                }
            }
        }

        let mut pos = t.len();
        for (idx, (k, _v)) in t.iter().enumerate() {
            if k <= &rank {
                pos = idx;
                break;
            }
        }
        t.insert(pos, (rank, value));
        t.commit();
    }

    /// Remove all instances in the vector having the specific value
    pub fn remove(&mut self, value: &T) {
        let mut t = self.vector.transaction();
        let mut entries = t.entries();
        while let Some(entry) = entries.next() {
            if &entry.1 == value {
                ObservableVectorTransactionEntry::remove(entry);
            }
        }
        t.commit();
    }

    /// Remove all instances in the vector having the specific value
    pub fn remove_where(&mut self, predicate: impl Fn(&T) -> bool) {
        let mut t = self.vector.transaction();
        let mut entries = t.entries();
        while let Some(entry) = entries.next() {
            if predicate(&entry.1) {
                ObservableVectorTransactionEntry::remove(entry);
            }
        }
        t.commit();
    }

    /// Returns the current list of values in order of their rank
    pub fn values(&self) -> Vec<&T> {
        self.vector.iter().map(|(_k, v)| v).collect()
    }

    /// Returns the current list of values in order of their rank
    pub fn values_cloned(&self) -> Vec<T> {
        self.vector.iter().map(|(_k, v)| v.clone()).collect()
    }

    pub fn batched_update_stream(&self) -> impl Stream<Item = Vec<VectorDiff<T>>> + use<K, T> {
        self.vector.subscribe().into_batched_stream().map(|l| {
            l.into_iter()
                .map(|v| match v {
                    VectorDiff::Append { values } => VectorDiff::Append {
                        values: values.into_iter().map(|(_k, v)| v).collect(),
                    },
                    VectorDiff::Clear => VectorDiff::Clear,
                    VectorDiff::PushFront { value } => VectorDiff::PushFront { value: value.1 },
                    VectorDiff::PushBack { value } => VectorDiff::PushBack { value: value.1 },
                    VectorDiff::PopFront => VectorDiff::PopFront,
                    VectorDiff::PopBack => VectorDiff::PopBack,
                    VectorDiff::Insert { index, value } => VectorDiff::Insert {
                        index,
                        value: value.1,
                    },
                    VectorDiff::Set { index, value } => VectorDiff::Set {
                        index,
                        value: value.1,
                    },
                    VectorDiff::Remove { index } => VectorDiff::Remove { index },
                    VectorDiff::Truncate { length } => VectorDiff::Truncate { length },
                    VectorDiff::Reset { values } => VectorDiff::Reset {
                        values: values.into_iter().map(|(_k, v)| v).collect(),
                    },
                })
                .collect()
        })
    }

    pub fn update_stream(&self) -> impl Stream<Item = VectorDiff<T>> + use<K, T> {
        self.vector.subscribe().into_stream().map(|v| match v {
            VectorDiff::Append { values } => VectorDiff::Append {
                values: values.into_iter().map(|(_k, v)| v).collect(),
            },
            VectorDiff::Clear => VectorDiff::Clear,
            VectorDiff::PushFront { value } => VectorDiff::PushFront { value: value.1 },
            VectorDiff::PushBack { value } => VectorDiff::PushBack { value: value.1 },
            VectorDiff::PopFront => VectorDiff::PopFront,
            VectorDiff::PopBack => VectorDiff::PopBack,
            VectorDiff::Insert { index, value } => VectorDiff::Insert {
                index,
                value: value.1,
            },
            VectorDiff::Set { index, value } => VectorDiff::Set {
                index,
                value: value.1,
            },
            VectorDiff::Remove { index } => VectorDiff::Remove { index },
            VectorDiff::Truncate { length } => VectorDiff::Truncate { length },
            VectorDiff::Reset { values } => VectorDiff::Reset {
                values: values.into_iter().map(|(_k, v)| v).collect(),
            },
        })
    }
}

struct GenericIndexVectorHandler();

impl GenericIndexVectorHandler {
    /// All instances of this element from the vector
    pub fn remove<T>(vector: &mut ObservableVector<T>, value: &T)
    where
        T: 'static + Clone + Eq,
    {
        let mut t = vector.transaction();
        let mut entries = t.entries();
        while let Some(entry) = entries.next() {
            if &*entry == value {
                ObservableVectorTransactionEntry::remove(entry);
            }
        }
        t.commit();
    }

    /// Returns the current list of values in order of when they were added
    pub fn values<T>(vector: &ObservableVector<T>) -> Vec<&T>
    where
        T: 'static + Clone + Eq,
    {
        vector.iter().collect()
    }

    pub fn update_stream<T>(
        vector: &ObservableVector<T>,
    ) -> impl Stream<Item = VectorDiff<T>> + use<T>
    where
        T: 'static + Clone + Eq,
    {
        vector.subscribe().into_stream()
    }
}

/// Keeps an index of items sorted by when they were added
/// latest first
pub struct LifoIndex<T>
where
    T: 'static + Clone + Eq,
{
    vector: ObservableVector<T>,
}

impl<T> LifoIndex<T>
where
    T: 'static + Clone + Eq,
{
    pub fn new_with(value: T) -> Self {
        let mut m = LifoIndex::default();
        m.insert(value);
        m
    }
    /// Insert the element at the front
    pub fn insert(&mut self, value: T) {
        self.vector.push_front(value);
    }

    /// All instances of this element from the vector
    pub fn remove(&mut self, value: &T) {
        GenericIndexVectorHandler::remove(&mut self.vector, value)
    }

    /// Returns the current list of values in order of when they were added
    pub fn values(&self) -> Vec<&T> {
        GenericIndexVectorHandler::values(&self.vector)
    }

    pub fn update_stream(&self) -> impl Stream<Item = VectorDiff<T>> + use<T> {
        GenericIndexVectorHandler::update_stream(&self.vector)
    }
}

impl<T> Default for LifoIndex<T>
where
    T: 'static + Clone + Eq,
{
    fn default() -> Self {
        Self {
            vector: Default::default(),
        }
    }
}

impl<T> Deref for LifoIndex<T>
where
    T: 'static + Clone + Eq,
{
    type Target = ObservableVector<T>;

    fn deref(&self) -> &Self::Target {
        &self.vector
    }
}

/// Keeps an index of items sorted by when they were added
/// latest last
pub struct FiloIndex<T>
where
    T: 'static + Clone + Eq,
{
    vector: ObservableVector<T>,
}

impl<T> FiloIndex<T>
where
    T: 'static + Clone + Eq,
{
    pub fn new_with(value: T) -> Self {
        let mut m = FiloIndex::default();
        m.insert(value);
        m
    }
    /// Insert the element at the front
    pub fn insert(&mut self, value: T) {
        self.vector.push_back(value);
    }

    /// All instances of this element from the vector
    pub fn remove(&mut self, value: &T) {
        GenericIndexVectorHandler::remove(&mut self.vector, value)
    }

    /// Returns the current list of values in order of when they were added
    pub fn values(&self) -> Vec<&T> {
        GenericIndexVectorHandler::values(&self.vector)
    }

    pub fn update_stream(&self) -> impl Stream<Item = VectorDiff<T>> + use<T> {
        GenericIndexVectorHandler::update_stream(&self.vector)
    }
}

impl<T> Default for FiloIndex<T>
where
    T: 'static + Clone + Eq,
{
    fn default() -> Self {
        Self {
            vector: Default::default(),
        }
    }
}

impl<T> Deref for FiloIndex<T>
where
    T: 'static + Clone + Eq,
{
    type Target = ObservableVector<T>;

    fn deref(&self) -> &Self::Target {
        &self.vector
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use futures::pin_mut;

    #[tokio::test]
    async fn test_ranked_index_for_u64() {
        let mut index = RankedIndex::<u64, &'static str>::default();
        index.insert(18, "18");
        index.insert(20, "20");
        index.insert(5, "5");
        index.insert(8, "8");

        assert_eq!(index.values(), [&"20", &"18", &"8", &"5",]);

        let stream = index.update_stream();

        index.remove(&"8");
        index.remove(&"18");

        assert_eq!(index.values(), [&"20", &"5"]);
        pin_mut!(stream);
        // ensure the right types and values
        assert!(matches!(
            stream.next().await.unwrap(),
            VectorDiff::Remove { index: 2 }
        ));
        assert!(matches!(
            stream.next().await.unwrap(),
            VectorDiff::Remove { index: 1 }
        ));
    }

    #[tokio::test]
    async fn test_lifo_index_for_u64() {
        let mut index = LifoIndex::<&'static str>::default();
        index.insert("18");
        index.insert("20");
        index.insert("5");
        index.insert("8");

        assert_eq!(index.values(), [&"8", &"5", &"20", &"18",]);

        let stream = index.update_stream();

        index.remove(&"18");
        index.remove(&"8");

        assert_eq!(index.values(), [&"5", &"20",]);
        pin_mut!(stream);
        // ensure the right types and values
        assert!(matches!(
            stream.next().await.unwrap(),
            VectorDiff::Remove { index: 3 }
        ));
        assert!(matches!(
            stream.next().await.unwrap(),
            VectorDiff::Remove { index: 0 }
        ));
    }
}
