# elementor

ok.
I have to get back to work, so here's what you've got here.

Task 1:
    had trouble with the API. this is a public repo so i am not going to 
    hardcode an API key here.
    so resorted to scraping with requests, which gives less the optimal results

    skipped implementing a db connection and calls
    (i hope that after reading my resume you trust i have the knowledge)

    coding.py 
        has a "Reputation" object
        Reputation has an exposed function called "query_url" which excepts a url 
        and returns it's reputation and categories

        Reputation holds an in memory record of all uptime queried records, 
        in production it should use either local or remote redis, depending on the scale

        coding.py can be imported, run as it is or used as and API when running app.py (flask app)

Task 2:
    in sql.txt

    

