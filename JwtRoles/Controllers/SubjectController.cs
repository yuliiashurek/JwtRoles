using JwtRoles.Data;
using JwtRoles.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtRoles.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SubjectsController : ControllerBase
    {
        private readonly IRepository<Subject> _subjectRepository;

        public SubjectsController(IRepository<Subject> subjectRepository)
        {
            _subjectRepository = subjectRepository;
        }

        // GET: api/subjects
        [HttpGet]
        [Authorize(Roles = "User,Admin")]
        public async Task<ActionResult<IEnumerable<Subject>>> GetSubjects()
        {
            var subjects = await _subjectRepository.GetAllAsync();
            return Ok(subjects);
        }

        // GET: api/subjects/{id}
        [HttpGet("{id}")]
        [Authorize(Roles = "User,Admin")]
        public async Task<ActionResult<Subject>> GetSubject(int id)
        {
            var subject = await _subjectRepository.GetByIdAsync(id);
            if (subject == null)
            {
                return NotFound();
            }
            return Ok(subject);
        }

        // POST: api/subjects
        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<Subject>> PostSubject(Subject subject)
        {
            if (subject == null)
            {
                return BadRequest();
            }

            await _subjectRepository.AddAsync(subject);

            // Return the created subject with a 201 status code
            return CreatedAtAction(nameof(GetSubject), new { id = subject.Id }, subject);
        }

        // PUT: api/subjects/{id}
        [HttpPut("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> PutSubject(int id, Subject subject)
        {
            if (id != subject.Id)
            {
                return BadRequest();
            }

            var existingSubject = await _subjectRepository.GetByIdAsync(id);
            if (existingSubject == null)
            {
                return NotFound();
            }

            await _subjectRepository.UpdateAsync(subject);
            return NoContent(); // 204 
        }

        // DELETE: api/subjects/{id}
        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteSubject(int id)
        {
            var existingSubject = await _subjectRepository.GetByIdAsync(id);
            if (existingSubject == null)
            {
                return NotFound();
            }

            await _subjectRepository.DeleteAsync(id);
            return NoContent(); // 204 
        }
    }
}
