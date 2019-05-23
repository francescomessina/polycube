#include <string>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <future>

struct Event {
  std::function<void()> f;
  std::promise<void> barrier;
};

class Namespace {
 public:
  static Namespace create(const std::string &name);
  static Namespace open(const std::string &name);

  static void stop();

  void execute(std::function<void()> f);
  void remove();
  void set_id(int id);

  ~Namespace();

 private:
  Namespace(const std::string &name, int fd);
  static void create_ns(const std::string &name);

  static void execute_in_worker(std::function<void()> f);

  std::string name_;
  std::string path_;
  int fd_;

  static std::thread executor;
  static std::condition_variable cv;
  static std::mutex mutex;
  static std::queue<Event*> queue;
  static bool finished;

  static void worker();
};
