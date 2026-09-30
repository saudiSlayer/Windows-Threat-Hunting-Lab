import csv


LOG_FILE = "data/windows_events.csv"


def load_events(filename):
    with open(filename, newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def investigate_value(events, search_value):

    matches = []

    search_value = search_value.lower()

    for event in events:

        searchable_fields = [
            event["timestamp"],
            event["event_id"],
            event["host"],
            event["user"],
            event["process"],
            event["parent_process"],
            event["command_line"],
            event["source_ip"],
            event["message"]
        ]

        if any(
            search_value in field.lower()
            for field in searchable_fields
            if field
        ):
            matches.append(event)

    return matches


def display_results(search_value, events):

    print("\n========================================")
    print("       WINDOWS EVENT INVESTIGATION")
    print("========================================")

    print(f"\nSearch: {search_value}")

    if not events:
        print("\nNo matching events found.")
        return

    print(f"\nEvents Found: {len(events)}")

    print("\nTimeline:")
    print("----------------------------------------")

    for event in events:

        print(
            f"{event['timestamp']} | "
            f"Event ID: {event['event_id']} | "
            f"User: {event['user']} | "
            f"Process: {event['process']} | "
            f"Source IP: {event['source_ip']}"
        )

    print("\nDetailed Events:")
    print("----------------------------------------")

    for event in events:

        print(f"\nTimestamp:       {event['timestamp']}")
        print(f"Event ID:        {event['event_id']}")
        print(f"Host:            {event['host']}")
        print(f"User:            {event['user']}")
        print(f"Process:         {event['process']}")
        print(f"Parent Process:  {event['parent_process']}")
        print(f"Source IP:       {event['source_ip']}")
        print(f"Message:         {event['message']}")

        if event["command_line"]:
            print(f"Command Line:    {event['command_line']}")


def main():

    events = load_events(LOG_FILE)

    search_value = input(
        "\nEnter a user, IP, process, or Event ID to investigate: "
    ).strip()

    matches = investigate_value(
        events,
        search_value
    )

    display_results(
        search_value,
        matches
    )


if __name__ == "__main__":
    main()