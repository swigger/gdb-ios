// fileread.h -- read files for gold   -*- C++ -*-

// Copyright 2006, 2007 Free Software Foundation, Inc.
// Written by Ian Lance Taylor <iant@google.com>.

// This file is part of gold.

// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
// MA 02110-1301, USA.

// Classes used to read data from binary input files.

#ifndef GOLD_FILEREAD_H
#define GOLD_FILEREAD_H

#include <list>
#include <map>
#include <string>

#include "options.h"
#include "token.h"

namespace gold
{

class Dirsearch;
class File_view;

// File_read manages a file descriptor for a file we are reading.  We
// close file descriptors if we run out of them, so this class reopens
// the file as needed.

class File_read
{
 public:
  File_read()
    : name_(), descriptor_(-1), object_count_(0), size_(0), token_(false),
      views_(), saved_views_(), contents_(NULL), mapped_bytes_(0),
      released_(true)
  { }

  ~File_read();

  // Open a file.
  bool
  open(const Task*, const std::string& name);

  // Pretend to open the file, but provide the file contents.  No
  // actual file system activity will occur.  This is used for
  // testing.
  bool
  open(const Task*, const std::string& name, const unsigned char* contents,
       off_t size);

  // Return the file name.
  const std::string&
  filename() const
  { return this->name_; }

  // Add an object associated with a file.
  void
  add_object()
  { ++this->object_count_; }

  // Remove an object associated with a file.
  void
  remove_object()
  { --this->object_count_; }

  // Lock the file for exclusive access within a particular Task::run
  // execution.  This means that the descriptor can not be closed.
  // This routine may only be called when the workqueue lock is held.
  void
  lock(const Task* t);

  // Unlock the descriptor, permitting it to be closed if necessary.
  void
  unlock(const Task* t);

  // Test whether the object is locked.
  bool
  is_locked() const;

  // Return the token, so that the task can be queued.
  Task_token*
  token()
  { return &this->token_; }

  // Release the file.  This indicates that we aren't going to do
  // anything further with it until it is unlocked.  This is used
  // because a Task which locks the file never calls either lock or
  // unlock; it just locks the token.  The basic rule is that a Task
  // which locks a file via the Task::locks interface must explicitly
  // call release() when it is done.  This is not necessary for code
  // which calls unlock() on the file.
  void
  release();

  // Return the size of the file.
  off_t
  filesize() const
  { return this->size_; }

  // Return a view into the file starting at file offset START for
  // SIZE bytes.  The pointer will remain valid until the File_read is
  // unlocked.  It is an error if we can not read enough data from the
  // file.  The CACHE parameter is a hint as to whether it will be
  // useful to cache this data for later accesses--i.e., later calls
  // to get_view, read, or get_lasting_view which retrieve the same
  // data.
  const unsigned char*
  get_view(off_t start, section_size_type size, bool cache);

  // Read data from the file into the buffer P starting at file offset
  // START for SIZE bytes.
  void
  read(off_t start, section_size_type size, void* p) const;

  // Return a lasting view into the file starting at file offset START
  // for SIZE bytes.  This is allocated with new, and the caller is
  // responsible for deleting it when done.  The data associated with
  // this view will remain valid until the view is deleted.  It is an
  // error if we can not read enough data from the file.  The CACHE
  // parameter is as in get_view.
  File_view*
  get_lasting_view(off_t start, section_size_type size, bool cache);

  // Mark all views as no longer cached.
  void
  clear_view_cache_marks();

  // A struct used to do a multiple read.
  struct Read_multiple_entry
  {
    // The file offset of the data to read.
    off_t file_offset;
    // The amount of data to read.
    section_size_type size;
    // The buffer where the data should be placed.
    unsigned char* buffer;

    Read_multiple_entry(off_t o, section_size_type s, unsigned char* b)
      : file_offset(o), size(s), buffer(b)
    { }
  };

  typedef std::vector<Read_multiple_entry> Read_multiple;

  // Read a bunch of data from the file into various different
  // locations.  The vector must be sorted by ascending file_offset.
  // BASE is a base offset to be added to all the offsets in the
  // vector.
  void
  read_multiple(off_t base, const Read_multiple&);

  // Dump statistical information to stderr.
  static void
  print_stats();

 private:
  // This class may not be copied.
  File_read(const File_read&);
  File_read& operator=(const File_read&);

  // Total bytes mapped into memory during the link.  This variable
  // may not be accurate when running multi-threaded.
  static unsigned long long total_mapped_bytes;

  // Current number of bytes mapped into memory during the link.  This
  // variable may not be accurate when running multi-threaded.
  static unsigned long long current_mapped_bytes;

  // High water mark of bytes mapped into memory during the link.
  // This variable may not be accurate when running multi-threaded.
  static unsigned long long maximum_mapped_bytes;

  // A view into the file.
  class View
  {
   public:
    View(off_t start, section_size_type size, const unsigned char* data,
	 bool cache, bool mapped)
      : start_(start), size_(size), data_(data), lock_count_(0),
	cache_(cache), mapped_(mapped), accessed_(true)
    { }

    ~View();

    off_t
    start() const
    { return this->start_; }

    section_size_type
    size() const
    { return this->size_; }

    const unsigned char*
    data() const
    { return this->data_; }

    void
    lock();

    void
    unlock();

    bool
    is_locked();

    void
    set_cache()
    { this->cache_ = true; }

    void
    clear_cache()
    { this->cache_ = false; }

    bool
    should_cache() const
    { return this->cache_; }

    void
    set_accessed()
    { this->accessed_ = true; }

    void
    clear_accessed()
    { this->accessed_= false; }

    bool
    accessed() const
    { return this->accessed_; }

   private:
    View(const View&);
    View& operator=(const View&);

    off_t start_;
    section_size_type size_;
    const unsigned char* data_;
    int lock_count_;
    bool cache_;
    bool mapped_;
    bool accessed_;
  };

  friend class View;
  friend class File_view;

  // Find a view into the file.
  View*
  find_view(off_t start, section_size_type size) const;

  // Read data from the file into a buffer.
  void
  do_read(off_t start, section_size_type size, void* p) const;

  // Find or make a view into the file.
  View*
  find_or_make_view(off_t start, section_size_type size, bool cache);

  // Clear the file views.
  void
  clear_views(bool);

  // The size of a file page for buffering data.
  static const off_t page_size = 8192;

  // Given a file offset, return the page offset.
  static off_t
  page_offset(off_t file_offset)
  { return file_offset & ~ (page_size - 1); }

  // Given a file size, return the size to read integral pages.
  static off_t
  pages(off_t file_size)
  { return (file_size + (page_size - 1)) & ~ (page_size - 1); }

  // The type of a mapping from page start to views.
  typedef std::map<off_t, View*> Views;

  // A simple list of Views.
  typedef std::list<View*> Saved_views;

  // The maximum number of entries we will pass to ::readv.
  static const size_t max_readv_entries = 128;

  // Use readv to read data.
  void
  do_readv(off_t base, const Read_multiple&, size_t start, size_t count);

  // File name.
  std::string name_;
  // File descriptor.
  int descriptor_;
  // The number of objects associated with this file.  This will be
  // more than 1 in the case of an archive.
  int object_count_;
  // File size.
  off_t size_;
  // A token used to lock the file.
  Task_token token_;
  // Buffered views into the file.
  Views views_;
  // List of views which were locked but had to be removed from views_
  // because they were not large enough.
  Saved_views saved_views_;
  // Specified file contents.  Used only for testing purposes.
  const unsigned char* contents_;
  // Total amount of space mapped into memory.  This is only changed
  // while the file is locked.  When we unlock the file, we transfer
  // the total to total_mapped_bytes, and reset this to zero.
  size_t mapped_bytes_;
  // Whether the file was released.
  bool released_;
};

// A view of file data that persists even when the file is unlocked.
// Callers should destroy these when no longer required.  These are
// obtained form File_read::get_lasting_view.  They may only be
// destroyed when the underlying File_read is locked.

class File_view
{
 public:
  // This may only be called when the underlying File_read is locked.
  ~File_view();

  // Return a pointer to the data associated with this view.
  const unsigned char*
  data() const
  { return this->data_; }

 private:
  File_view(const File_view&);
  File_view& operator=(const File_view&);

  friend class File_read;

  // Callers have to get these via File_read::get_lasting_view.
  File_view(File_read& file, File_read::View* view, const unsigned char* data)
    : file_(file), view_(view), data_(data)
  { }

  File_read& file_;
  File_read::View* view_;
  const unsigned char* data_;
};

// All the information we hold for a single input file.  This can be
// an object file, a shared library, or an archive.

class Input_file
{
 public:
  Input_file(const Input_file_argument* input_argument)
    : input_argument_(input_argument), found_name_(), file_(),
      is_in_sysroot_(false)
  { }

  // Create an input file with the contents already provided.  This is
  // only used for testing.  With this path, don't call the open
  // method.
  Input_file(const Task*, const char* name, const unsigned char* contents,
	     off_t size);

  // Open the file.  If the open fails, this will report an error and
  // return false.
  bool
  open(const General_options&, const Dirsearch&, const Task*);

  // Return the name given by the user.  For -lc this will return "c".
  const char*
  name() const
  { return this->input_argument_->name(); }

  // Return the file name.  For -lc this will return something like
  // "/usr/lib/libc.so".
  const std::string&
  filename() const
  { return this->file_.filename(); }

  // Return the name under which we found the file, corresponding to
  // the command line.  For -lc this will return something like
  // "libc.so".
  const std::string&
  found_name() const
  { return this->found_name_; }

  // Return the position dependent options.
  const Position_dependent_options&
  options() const
  { return this->input_argument_->options(); }

  // Return the file.
  File_read&
  file()
  { return this->file_; }

  const File_read&
  file() const
  { return this->file_; }

  // Whether we found the file in a directory in the system root.
  bool
  is_in_sysroot() const
  { return this->is_in_sysroot_; }

 private:
  Input_file(const Input_file&);
  Input_file& operator=(const Input_file&);

  // The argument from the command line.
  const Input_file_argument* input_argument_;
  // The name under which we opened the file.  This is like the name
  // on the command line, but -lc turns into libc.so (or whatever).
  // It only includes the full path if the path was on the command
  // line.
  std::string found_name_;
  // The file after we open it.
  File_read file_;
  // Whether we found the file in a directory in the system root.
  bool is_in_sysroot_;
};

} // end namespace gold

#endif // !defined(GOLD_FILEREAD_H)
