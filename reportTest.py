__author__ = 'duminduk'

file=open("report.html","w")

file.write("""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
        "http://www.w3.org/TR/html4/loose.dtd">
        <html>
        <head>
            <title>Bridge Status Report</title>
            <style>
                table, th, td {
                    border: 1px solid black;
                    border-collapse: collapse;
                }
                th, td {
                    padding: 5px;
                    text-align: left;
            }
            </style>
        </head>
        <body>
        """)

file.write("""<table style="width:100%">
      <caption>Monthly savings</caption>
      <tr>
        <th>Month</th>
        <th>Savings</th>
      </tr>
      <tr>
        <td>January</td>
        <td>$100</td>
      </tr>
      <tr>
        <td>February</td>
        <td>$50</td>
      </tr>
    </table>""")


file.write("""
        </body>
        </html>""")


file.close()