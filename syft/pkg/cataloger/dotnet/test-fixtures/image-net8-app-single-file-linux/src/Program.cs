using System;
using Humanizer;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;


namespace IndirectDependencyExample
{
    class Program
    {
        static void Main(string[] args)
        {
            string runtimeInfo = "hello world!\n";
            Console.WriteLine(runtimeInfo);


            Console.WriteLine($"\"this_is_a_test\" to title case: {"this_is_a_test".Humanize(LetterCasing.Title)}");

            const string jsonString = @"
            {
                ""message"": ""Hello from JSON!"",
                ""details"": {
                    ""timestamp"": ""2025-03-26T12:00:00Z"",
                    ""version"": ""1.0.0"",
                    ""metadata"": {
                        ""author"": ""Claude"",
                        ""environment"": ""Development""
                    }
                },
                ""items"": [
                    {
                        ""id"": 1,
                        ""name"": ""Item One""
                    },
                    {
                        ""id"": 2,
                        ""name"": ""Item Two""
                    }
                ]
            }";

            JObject jsonObject = JObject.Parse(jsonString);

            string message = (string)jsonObject["message"];
            Console.WriteLine($"Message: {message}");
        }
    }
}