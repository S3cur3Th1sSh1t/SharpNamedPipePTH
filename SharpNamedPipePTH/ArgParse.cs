using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpNamedPipePTH
{
    public static class ArgParse
    {
        //Argument parsing class from Rubeus (https://github.com/GhostPack/Rubeus/)
        //Author: @Harmj0y

        public static ArgumentParserResult Parse(IEnumerable<string> args)
        {
            var arguments = new Dictionary<string, string>();
            try
            {
                foreach (var argument in args)
                {
                    var idx = argument.IndexOf(':');
                    if (idx > 0)
                        arguments[argument.Substring(0, idx).ToLower()] = argument.Substring(idx + 1);
                    else if (argument.ToLower() == "-debug")
                        arguments["debugging"] = "true";
                    else if (argument.ToLower() == "-h")
                        arguments["showhelp"] = "true";
                    else if (argument.ToLower() == "-help")
                        arguments["showhelp"] = "true";
                    else if (argument.ToLower() == "-checkadmin")
                        arguments["admincheck"] = "true";
                    else if (argument.ToLower() == "-forcesmb1")
                        arguments["forcesmb1"] = "true";
                    else if (argument.ToLower() == "-smb1")
                        arguments["forcesmb1"] = "true";
                    else if (argument.ToLower() == "-comspec")
                        arguments["comspec"] = "true";
                    else
                        arguments[argument] = string.Empty;
                }

                return ArgumentParserResult.Success(arguments);
            }
            catch (System.Exception ex)
            {
                Console.WriteLine(ex.Message);
                return ArgumentParserResult.Failure();
            }
        }
    }
    public class ArgumentParserResult
    {
        public bool ParsedOk { get; }
        public Dictionary<string, string> Arguments { get; }

        private ArgumentParserResult(bool parsedOk, Dictionary<string, string> arguments)
        {
            ParsedOk = parsedOk;
            Arguments = arguments;
        }

        public static ArgumentParserResult Success(Dictionary<string, string> arguments)
            => new ArgumentParserResult(true, arguments);

        public static ArgumentParserResult Failure()
            => new ArgumentParserResult(false, null);
    }
}
