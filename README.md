### Introduction
This is a Rust-based Solana key generator that creates and stores key pairs in a MongoDB database. The keys are encrypted using AES-256-CBC encryption.

### Installation
1. Clone the repository:
   ```
   git clone https://github.com/khuzama98/solana-key-generator.git
   cd solana-key-generator
   ```

2. Install the required dependencies:
   ```
   cargo build
   ```

3. Set up the environment variables in a `.env` file:
   ```
   MONGODB_URI=your_mongodb_uri
   ENCRYPTION_KEY=your_32_byte_hex_encryption_key
   TARGET_SUFFIX=desired_public_key_suffix
   ```

### Usage
To run the key generator:
```
cargo run
```

For Production release:
```
cargo build --release
```

The program will continuously generate key pairs that match the specified `TARGET_SUFFIX` and store them in the MongoDB database.

### Code Overview
The main function initializes the environment, sets up MongoDB client options, and spawns a task to generate key pairs in parallel. It also handles the shutdown signal (Ctrl+C) to gracefully stop the program.

### Contributing
Feel free to open issues or submit pull requests if you have suggestions or improvements.

### License
This project is licensed under the MIT License.
