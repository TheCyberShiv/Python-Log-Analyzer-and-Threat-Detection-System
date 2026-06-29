import csv
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet


def generate_csv(ip_count):

    report_data = []

    for ip, count in ip_count.items():

        if count >= 3:

            report_data.append([
                "Brute Force Attack",
                ip,
                count,
                "High",
                "T1110"
            ])

    with open("reports/report.csv", "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Alert Name",
            "IP Address",
            "Attempts",
            "Severity",
            "MITRE ID"
        ])

        writer.writerows(report_data)
        print("✅ CSV Report Generated Successfully!")


def generate_pdf(logs, ip_count):

    doc = SimpleDocTemplate("reports/Incident_Report.pdf")

    styles = getSampleStyleSheet()

    story = []

    story.append(Paragraph("<b>SOC Incident Report</b>", styles["Title"]))

    story.append(Paragraph("<br/>", styles["Normal"]))

    story.append(Paragraph(f"Total Logs Analysed : {len(logs)}", styles["Normal"]))

    story.append(Paragraph("<br/>", styles["Normal"]))

    for ip, count in ip_count.items():

        if count >= 3:

            story.append(
                Paragraph(
                    f"""
                    <b>Alert</b><br/>
                    Attack : Brute Force<br/>
                    IP : {ip}<br/>
                    Attempts : {count}<br/>
                    Severity : High<br/>
                    MITRE : T1110
                    """,
                    styles["Normal"]
                )
            )

            story.append(Paragraph("<br/>", styles["Normal"]))

    doc.build(story)

    print("✅ PDF Report Generated")