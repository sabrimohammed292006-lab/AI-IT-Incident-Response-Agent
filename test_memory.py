
import asyncio

from agents import SQLiteSession

from config import DATABASE_PATH


async def main():
    session = SQLiteSession(
        "INC-TEST-001",
        DATABASE_PATH,
    )

    history = await session.get_items()

    print("\n--- Memory Test Result ---")
    print("Database:", DATABASE_PATH)
    print("Session ID: INC-TEST-001")
    print("Saved items:", len(history))

    if history:
        print("Session history exists.")
    else:
        print("No saved conversation items found.")

    session.close()


if __name__ == "__main__":
    asyncio.run(main())
