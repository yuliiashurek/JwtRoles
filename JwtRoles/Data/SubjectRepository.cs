using JwtRoles.Entities;
using Microsoft.EntityFrameworkCore;

namespace JwtRoles.Data
{
    public class SubjectRepository : IRepository<Subject>
    {
        private readonly AppDbContext _context;

        public SubjectRepository(AppDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<Subject>> GetAllAsync()
        {
            return await _context.Subjects.ToListAsync();
        }

        public async Task<Subject> GetByIdAsync(int id)
        {
            return await _context.Subjects.FindAsync(id);
        }

        public async Task AddAsync(Subject entity)
        {
            await _context.Subjects.AddAsync(entity);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(Subject entity)
        {
            _context.Subjects.Update(entity);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(int id)
        {
            var subject = await GetByIdAsync(id);
            if (subject != null)
            {
                _context.Subjects.Remove(subject);
                await _context.SaveChangesAsync();
            }
        }
    }
}
