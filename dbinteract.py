import psycopg2
from config import config
import re

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--vuln", help="Name of vulnerbility")
    parser.add_argument("-i", "--ignore", help="String to ignore")
    parser.add_argument("-y", "--year", help="Year to search")
    parser.add_argument("-r", "--regex", help="Search via regex")
    return parser.parse_args()

class Postgres():

    def create_sql(self, issues, cur):
        data = []

        for i in issues:
            for issue in issues[i]:
                issue_val = []
                for item in issue:
                    val = item[1]
                    if type(val) == list:
                        val = ', '.join(val)
                    issue_val.append(val.strip())
                issue_val = tuple(issue_val)
                data.append(issue_val)

        args_str = ','.join(cur.mogrify("(%s,%s,%s,%s,%s,%s,%s)", x).decode('utf8') for x in data)
        sql = 'INSERT INTO reports (report_name, app_url, title, resources, severity, impact, recommendations) VALUES {}'.format(
            args_str)

        return sql, data

    def connect(self):
        try:
            # read database configuration
            params = config()
            # connect to the PostgreSQL database
            conn = psycopg2.connect(**params)
            # create a new cursor
            cur = conn.cursor()
            return cur, conn
        except (Exception, psycopg2.DatabaseError) as error:
            print(error)

    def run_sql(self, conn, cur):
        cur.execute(sql, data)
        conn.commit()

def get_vuln(reports, vuln, ignore="This will never exist 1234567890"):
    i = 0
    titles = []
    for x in reports:
        for title in reports[x]:
            if vuln in title and ignore not in title:
                i+=1
                titles.append(title)
                print()
                print(x)
                print(title)
                print(reports[x])
    print(i)
    return titles

def get_vuln_re_year(reports, vuln, year, ignore="This will never exist 1234567890"):
    i = 0
    titles = []
    if year == '2020':
        divide = 484
    elif year == '2019':
        divide = 934
    elif year == '2018':
        divide = 613
    elif year == '2017':
        divide = 96
    for x in reports:
        for title in reports[x]:
            if re.search(vuln, title) and ignore not in title and year in x:
                i+=1
                titles.append(title)
                print()
                print(x)
                print(title)
                print(reports[x])
    print(i)
    print((i/divide)*100)
    return titles

def get_vuln_re(reports, vuln, ignore="This will never exist 1234567890"):
    i = 0
    titles = []
    for x in reports:
        for title in reports[x]:
            if re.search(vuln, title) and ignore not in title:
                i+=1
                titles.append(title)
                print()
                print(x)
                print(title)
                print(reports[x])
    print(i)
    return titles

def related_vulns(reports, vuln, related):
    titles = []
    all_titles = []
    found = False
    i = 0
    e = 0
    for x in reports:
        for title in reports[x]:
            if vuln in title:
                i +=1
                found = True
                break
        if found == True:
            relateds = []
            for title in reports[x]:
                all_titles.append(title)
                if related in title:
                    e += 1
                    relateds.append(title)
            if len(relateds) > 0:
                titles.append(relateds)
        found = False
    print(i)
    print(e)
    print(all_titles)
    return titles


def main():
    psql = Postgres()
    cur, conn = psql.connect()
    reports = {}
    cur.execute('select * from reports')
    data = cur.fetchall()
    for i in data:
        title = i[0]
        url = i[1]
        sev = i[2]
        desc = i[3]
        rec = i[4]
        rn = i[5]
        if rn in reports:
            reports[rn].append(title)
        else:
            reports[rn] = [title]
    pass


if __name__ == "__main__":
    main()
