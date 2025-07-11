pub mod example;
pub mod generic;


#[derive(Debug, Serialize, Deserialize)]
pub enum Response<T: Serialize + Deserialize, E: Serialize + Deserialize> {
    Error(generic::GenericError<E>),
    Ok(T),
}