pub enum Error{
    PersonasFull,
    PersonaNotFound,
    SigningError(ed25519_dalek::ed25519::Error)
}