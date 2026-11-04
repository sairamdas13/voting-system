# Online Voting System (demo)

1. Open the .env file: paste your MongoDB connection string after MONGO_URI= and set your own OFFICER_KEY
2. npm install
3. npm start
4. Open http://localhost:3000

First use:
- Login as -> Officer -> Register as Officer (needs OFFICER_KEY from .env)
- Login as officer -> Manage voters -> add voters (ID, name, password)
- Voters login with the ID and password the officer gave them

Only officers can add/delete voters and see the vote count.
To reset all votes: mongosh -> use votingdb; db.votes.deleteMany({})
"# voting-system" 
