using System.Collections.Generic;
using System.Linq;

public record UserClientRole(string ClientId, string SubjectId, string Role);

public interface IUserClientRoleRepository
{
    void Add(UserClientRole association);
    List<string> GetRoles(string clientId, string subjectId);
}

public class InMemoryUserClientRoleRepository : IUserClientRoleRepository
{
    private readonly List<UserClientRole> _associations = new();

    public void Add(UserClientRole association)
    {
        _associations.Add(association);
    }

    public List<string> GetRoles(string clientId, string subjectId)
    {
        return _associations
            .Where(a => a.ClientId == clientId && a.SubjectId == subjectId)
            .Select(a => a.Role)
            .Distinct()
            .ToList();
    }
}