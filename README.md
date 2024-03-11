

# Private URL Generator

## Introduction

The Private URL Generator is an ongoing project that aims to provide a mechanism for generating encrypted private URLs. The generated URLs are intended to restrict access to authorized users, and the project is currently under development.

## Features

- **Generate Private URL:** Input a URL, and the application will generate an encrypted private URL.
- **Access Private URL:** Users can access the original URL by entering the encrypted URL, which is decrypted server-side. Access control measures are in progress.

## Technologies Used

- [Go](https://golang.org/) - The programming language used for server-side development.
- [Gorilla](https://github.com/gorilla/mux) - Web toolkit for routing in Go.
- [crypto/aes](https://golang.org/pkg/crypto/aes/) - Go standard library package for AES encryption.

## Setup

1. Install Go by following the instructions on [golang.org](https://golang.org/doc/install).
2. Install the Gorilla toolkit:

    ```bash
    go get -u github.com/gorilla/mux
    ```

3. Run the application:

    ```bash
    go run private_url_generator.go
    ```

4. Access the application in your web browser at `http://127.0.0.1:8080/`.

## Usage (Incomplete)

1. Visit the homepage and enter a URL in the form.
2. Submit the form to generate an encrypted private URL.
3. (In Progress) Implementing access control measures for secure URL access.

## Security Considerations

- **Security Measures (Incomplete):** This project is currently under development and lacks complete security measures. Ensure the implementation of secure key management, handle URL mappings securely, and implement robust user authentication and authorization.

## Contributing

Contributions are welcome! If you find any issues, have suggestions for improvements, or would like to contribute to the project's completion, please open an issue or submit a pull request.
