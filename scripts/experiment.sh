# Create the neccessary fabric environment and deploy the chaincode

./network.sh down
./network.sh up createChannel -s couchdb
./network.sh deployCC -ccn experiment -ccp ../myChaincode/experiment -ccl go
