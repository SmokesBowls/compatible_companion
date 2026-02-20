# Compatible Companion

## Purpose
The Compatible Companion project is designed to provide interoperability between various services and platforms, enhancing usability and functionality.

## Architecture
The project's architecture is modular, allowing easy integration of components and services. It is built with a microservices approach to ensure scalability and maintainability.

## Components
- **Service A**: Responsible for x functionality.
- **Service B**: Manages y tasks.
- **Service C**: Handles z operations.

## Security Features
- **Authentication**: Utilizes OAuth 2.0 for secure login.
- **Data Encryption**: All sensitive data is encrypted using AES-256.
- **Regular Audits**: The system undergoes regular security audits to ensure compliance and safety.

## Demo Instructions
1. Clone the repository: `git clone https://github.com/SmokesBowls/compatible_companion.git`
2. Navigate into the project directory: `cd compatible_companion`
3. Run the demo with `./run_demo.sh`

## API Endpoints
- **GET /api/v1/resource**: Fetches resources.
- **POST /api/v1/resource**: Creates a new resource.
- **PUT /api/v1/resource/{id}**: Updates a resource.

## Daemon Setup
To set up the daemon, follow these steps: 
1. Install dependencies: `npm install`
2. Start the daemon: `npm run start-daemon`

## UI Launcher
To start the UI: 
1. Navigate to the UI directory: `cd ui/`
2. Launch the UI: `npm start`

## Snapshot/Compaction System
The snapshot and compaction system operates on a schedule to optimize data storage and retrieval. Configure settings in the settings.json file.

## Testing Framework
The project uses Jest for unit testing. Run tests with the following command: 
```bash
npm test
```

## Data Files
Data files are located in the `/data` directory and are structured in a JSON format.

## Configuration
Configuration settings can be found in the `config.yml` file. Customize according to your environment.

## Usage Examples
- **Creating a Resource**:  
  ```bash
  curl -X POST /api/v1/resource -d '{"name": "example"}'
  ```
- **Fetching Resources**:  
  ```bash
  curl -X GET /api/v1/resource
  ```

For additional information, refer to the [Wiki](https://github.com/SmokesBowls/compatible_companion/wiki).