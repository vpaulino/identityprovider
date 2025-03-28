using System.Collections.Generic;

public record User(string SubjectId, string Name, string Email);

public interface IUserStore
{
    void Add(User user);
    User Get(string username);
    IEnumerable<User> GetAll();
}

public class InMemoryUserStore : IUserStore
{
    private readonly Dictionary<string, User> _users = new();


    public User? Get(string username) =>
        _users.TryGetValue(username, out var user) ? user : null;

    public void Add(User user) =>
      _users[user.SubjectId] = user;

    public IEnumerable<User> GetAll() => _users.Values;
}