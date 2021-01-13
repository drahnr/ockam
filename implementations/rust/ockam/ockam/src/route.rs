use crate::address::{Address, Addressable};
use alloc::collections::VecDeque;

#[cfg(feature = "json")]
use serde::Serialize;

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg(feature = "json")]
#[derive(Serialize)]
pub struct RouteEntry {
    address: Address,
}

impl Addressable for RouteEntry {
    fn address(&self) -> Address {
        self.address.clone()
    }
}

impl Into<RouteEntry> for Address {
    fn into(self) -> RouteEntry {
        RouteEntry { address: self }
    }
}

impl Into<RouteEntry> for &str {
    fn into(self) -> RouteEntry {
        Address::from(self).into()
    }
}

#[derive(Clone, Default, Debug, Eq, PartialEq)]
#[cfg(feature = "json")]
#[derive(Serialize)]
pub struct Route {
    path: VecDeque<RouteEntry>,
}

impl Route {
    pub fn append(&mut self, entry: RouteEntry) {
        self.path.push_back(entry);
    }

    pub fn take_front(&mut self) -> Option<RouteEntry> {
        self.path.pop_front()
    }

    pub fn front(&self) -> Option<&RouteEntry> {
        self.path.front()
    }

    pub fn is_empty(&self) -> bool {
        self.path.is_empty()
    }
}

#[cfg(test)]
mod test {
    use crate::route::Route;
    use alloc::string::ToString;

    #[test]
    fn route_test() {
        let mut route = Route::default();

        route.append("sender".into());
        route.append("printer".into());

        while !route.is_empty() {
            if let Some(entry) = route.take_front() {
                assert!(!entry.address.to_string().is_empty())
            }
        }
    }
}
